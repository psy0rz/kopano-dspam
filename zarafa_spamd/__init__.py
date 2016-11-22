#!/usr/bin/env python
from contextlib import closing
import dbhash
import fcntl
import os.path
import time
import sys
import pprint
import subprocess
import re

import zarafa
from zarafa import log_exc, Config
sys.path.insert(0, os.path.dirname(__file__)) # XXX for __import__ to work

"""
zarafa-spamd v1 - monitors mail-movements to retrain your spamfilter

(C)2016 Edwin Eefting (edwin@datux.nl), based on zarafa-search and the excellent python-zarafa API.

Copyright 2005 - 2015  Zarafa B.V. and its licensors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License, version 3,
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see http://www.gnu.org/licenses/.


"""

CONFIG = {
    'run_as_user': Config.string(default="zarafa"),
    'run_as_group': Config.string(default="zarafa"),

    #spamd specific settings:
    'spamd_path': Config.string(default='/var/lib/zarafa/spamd/'),
    'process_delay': Config.integer(default=1),

    'header_result': Config.string(default="X-DSPAM-Result"),
    'header_result_spam': Config.string(default="Spam"),

    'header_user': Config.string(default="X-DSPAM-Recipient"),
    'header_id': Config.string(default="X-DSPAM-Signature"),

    'retrain_script': Config.string(default="/etc/zarafa/userscripts/zarafa-spamd-retrain"),

    #filter dangerous characters before calling shell script
    'shell_filter_regex': Config.string(default="[^a-zA-Z0-9_,.-]"),
}

def db_get(db_path, key):
    """ get value from db file """
    with closing(dbhash.open(db_path, 'c')) as db:
        return db.get(key)

def db_put(db_path, key, value):
    """ store key, value in db file """
    with open(db_path+'.lock', 'w') as lockfile:
        fcntl.flock(lockfile.fileno(), fcntl.LOCK_EX)
        with closing(dbhash.open(db_path, 'c')) as db:
            db[key] = value


class ItemImporter:
    """ called by python-zarafa syncer for every item thats updated or deleted """

    def __init__(self, *args):
        self.server, self.config, self.log = args
        self.retrained_db = os.path.join(self.config['spamd_path'], self.server.guid+'_retrained')

    def call_retrain_script(self, spam_user, spam_id, classification, undo):
        cmd = [
            self.config['retrain_script'],
            re.sub(self.config['shell_filter_regex'], "", spam_user),
            re.sub(self.config['shell_filter_regex'], "", spam_id),
            re.sub(self.config['shell_filter_regex'], "", classification),
            re.sub(self.config['shell_filter_regex'], "", undo )
            ]


        self.log.debug("Starting: %s" % cmd)
        p=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output=p.communicate()[0]
        if output:
            self.log.error(self.config['retrain_script']+" output:\n"+output)

        if p.returncode!=0:
            self.log.error("Command exited with code %d" % p.returncode)
        else:
            self.log.debug("Command exited with code %d" % p.returncode)

    def train(self, spam_user, spam_id, classification, undo):
        if undo=="undo":
            db_put(self.retrained_db, spam_user+"-"+spam_id, None)
        else:
            db_put(self.retrained_db, spam_user+"-"+spam_id, "1")

        self.call_retrain_script(spam_user, spam_id, classification, undo)

    def update(self, item, flags):

        with log_exc(self.log):

            #only process mails that are not in wastebasket
            if item.message_class != 'IPM.Note' or item.folder == item.store.wastebasket:
                pass
            #is the document is processed not processed by the spamfilter at all?
            elif item.header(self.config['header_result'])==None:
                log_str="folder '%s', subject '%s': " % (item.folder.name, item.subject)
                self.log.debug(log_str+"ignored, no spam-headers found")
            else:

                detected_as_spam = ( item.header(self.config['header_result'])==self.config['header_result_spam'] )
                spam_user = item.header(self.config['header_user'])
                spam_id   = item.header(self.config['header_id'])
                retrained = ( db_get(self.retrained_db, spam_user+"-"+spam_id) == "1" )
                in_spamfolder = ( item.folder == item.store.junk )

                log_str="spam_user: %s, folder: '%s', subject: '%s', spam_id: %s, detected_as_spam: %s, retrained: %s, in_spamfolder: %s, CONCLUSION: " % ( spam_user, item.folder.name, item.subject, spam_id, detected_as_spam, retrained, in_spamfolder)

                if detected_as_spam:
                    if in_spamfolder:
                        if retrained:
                             self.log.info(log_str+"moved back to spam again: undo training as innocent")
                             self.train(spam_user, spam_id, "spam", "undo")
                        else:
                             self.log.debug(log_str+"spam already in spam folder, no action needed")
                    #in non-spam folder
                    else:
                        if not retrained:
                             self.log.info(log_str+"moved from spam: retraining as innocent")
                             self.train(spam_user, spam_id, "innocent", "")
                        else:
                             self.log.debug(log_str+"moved from spam, already retrained")

                #not detected as spam
                else:
                    if in_spamfolder:
                        if not retrained:
                             self.log.info(log_str+"moved to spam: retraining as spam")
                             self.train(spam_user, spam_id, "spam", "")
                        else:
                             self.log.debug(log_str+"moved to spam: already retrained")

                    #in non-spam folder
                    else:
                        if retrained:
                             self.log.info(log_str+"moved from spam again: undo training as spam")
                             self.train(spam_user, spam_id, "innocent", "undo")
                        else:
                             self.log.debug(log_str+"normal mail already in normal folder: no action needed")

    def delete(self, item, flags):

        with log_exc(self.log):
            self.log.debug('deleted document with sourcekey %s' % ( item.sourcekey ))

class Service(zarafa.Service):
    """ main spamd process """

    def main(self):
        """ start initial syncing if no state found. then start query process and switch to incremental syncing """

        spamd_path = self.config['spamd_path']
        os.umask(0077)
        if not os.path.exists(spamd_path):
            os.makedirs(spamd_path)
        state_db = os.path.join(spamd_path, self.server.guid+'_state')
        state = db_get(state_db, 'SERVER')
        if state:
            self.log.debug('found previous server sync state: %s' % state)
        else:
            state=self.server.state
            self.log.debug('no previous state found, starting from state: %s' % state)
            db_put(state_db, 'SERVER', state)

        #incremental syncer
        self.log.info('startup complete, monitoring mail movements')
        importer = ItemImporter(self.server, self.config, self.log)
        while True:
            with log_exc(self.log):
                new_state = self.server.sync(importer, state, log=self.log)
                if new_state != state:
                    state = new_state
                    db_put(state_db, 'SERVER', state)
                    self.log.debug('saved server sync state = %s' % state)
            time.sleep(self.config['process_delay'])


def main():
    parser = zarafa.parser('ckpsF') # select common cmd-line options
    options, args = parser.parse_args()
    service = Service('spamd', config=CONFIG, options=options)
    service.start()

if __name__ == '__main__':
    main()
