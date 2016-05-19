#!/usr/bin/env python
from contextlib import closing
import dbhash
import fcntl
import os.path
from Queue import Empty
from multiprocessing import Queue
import time
import sys
import pprint

import plaintext
import zarafa
from zarafa import log_exc, Config
sys.path.insert(0, os.path.dirname(__file__)) # XXX for __import__ to work

"""
zarafa-search v3 - a process-based indexer and query handler built on python-zarafa

initial indexing is performed in parallel using N instances of class IndexWorker, fed with a queue containing folder-ids.

incremental indexing is later performed in the same fashion. when there is no pending work, we
check if there are reindex requests and handle one of these (again parallellized). so incremental syncing is currently paused
during reindexing.

search queries from outlook/webapp are dealt with by a single instance of class SearchWorker.

since ICS does not know for deletion changes which store they belong to, we remember ourselves using a berkeleydb file ("serverguid_mapping").

we also maintain folder and server ICS states in a berkeleydb file, for example so we can resume initial indexing ("serverguid_state").
after initial indexing folder states are not updated anymore.

the used search engine is pluggable, but by default we use xapian (plugin_xapian.py).

a tricky bit is that outlook/exchange perform 'prefix' searches by default and we want to be compatible with this, so terms get an
implicit '*' at the end. not every search engine may perform well for this, but we could make this configurable perhaps.

"""

CONFIG = {
    'coredump_enabled': Config.ignore(),
    'index_attachments': Config.boolean(default=True),
    'index_attachment_extension_filter': Config.ignore(),
    'index_attachment_mime_filter': Config.ignore(),
    'index_attachment_max_size': Config.size(default=2**24),
    'index_attachment_parser': Config.ignore(),
    'index_attachment_parser_max_memory': Config.ignore(),
    'index_attachment_parser_max_cputime': Config.ignore(),
    # 0x007D: PR_TRANSPORT_MESSAGE_HEADERS
    # 0x0064: PR_SENT_REPRESENTING_ADDRTYPE
    # 0x0C1E: PR_SENDER_ADDRTYPE
    # 0x0075: PR_RECEIVED_BY_ADDRTYPE
    # 0x678E: PR_EC_IMAP_BODY
    # 0x678F: PR_EC_IMAP_BODYSTRUCTURE
    # 0x001A: PR_MESSAGE_CLASS # XXX add to cfg
    'index_exclude_properties': Config.integer(multiple=True, base=16, default=[0x007D, 0x0064, 0x0C1E, 0x0075, 0x678E, 0x678F, 0x001A]),
    'index_path': Config.string(default='/var/lib/zarafa/search/'),
    'index_processes': Config.integer(default=1),
    'limit_results': Config.integer(default=0),
    'optimize_age': Config.ignore(),
    'optimize_start': Config.ignore(),
    'optimize_stop': Config.ignore(),
    'run_as_user': Config.string(default="zarafa"),
    'run_as_group': Config.string(default="zarafa"),
    'search_engine': Config.string(default='xapian'),
    'server_bind_name': Config.string(default='file:///var/run/zarafad/search.sock'),
    'ssl_private_key_file': Config.path(default=None, check=False), # XXX don't check when default=None?
    'ssl_certificate_file': Config.path(default=None, check=False),
    'term_cache_size': Config.size(default=64000000),

    'process_delay': Config.integer(default=1),

    'header_result': Config.string(default="X-DSPAM-Result"),
    'header_result_spam': Config.string(default="Spam"),

    'header_user': Config.string(default="X-DSPAM-Recipient"),
    'header_id': Config.string(default="X-DSPAM-Signature"),
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


class FolderImporter:
    """ tracks changes for a specific folder (the actual changed items) """

    def __init__(self, *args):
        self.serverid, self.config, self.log, self.store, self.folder = args
        self.changes = self.deletes = self.attachments = 0
        self.retrained_db = os.path.join(self.config['index_path'], self.serverid+'_retrained')
        self.excludes = set(self.config['index_exclude_properties']+[0x1000, 0x1009, 0x1013, 0x678C]) # PR_BODY, PR_RTF_COMPRESSED, PR_HTML, PR_EC_IMAP_EMAIL
        self.term_cache_size = 0

    def update(self, item, flags):
        """ called for a new or changed item; get mapi properties, attachments and pass to indexing plugin """

        with log_exc(self.log):
            self.changes += 1
            storeid, folderid, sourcekey, docid = item.storeid, item.folderid, item.sourcekey, item.docid
            # doc = {'serverid': self.serverid, 'storeid': storeid, 'folderid': folderid, 'docid': docid, 'sourcekey': item.sourcekey}
            # for prop in item.props():
            #     if prop.id_ not in self.excludes:
            #         if isinstance(prop.value, unicode):
            #             if prop.value:
            #                 doc['mapi%d' % prop.id_] = prop.value
            #         elif isinstance(prop.value, list):
            #             doc['mapi%d' % prop.id_] = u' '.join(x for x in prop.value if isinstance(x, unicode))
            # attach_text = []
            # if self.config['index_attachments']:
            #     for a in item.attachments():
            #         self.log.debug('checking attachment (filename=%s, size=%d, mimetag=%s)' % (a.filename, len(a), a.mimetype))
            #         if 0 < len(a) < self.config['index_attachment_max_size'] and a.filename != 'inline.txt': # XXX inline attachment check
            #             self.attachments += 1
            #             attach_text.append(plaintext.get(a, mimetype=a.mimetype, log=self.log))
            #         attach_text.append(u' '+(a.filename or u''))
            # doc['mapi4096'] = item.body.text + u' ' + u' '.join(attach_text) # PR_BODY
            # doc['mapi3588'] = u' '.join([a.name + u' ' + a.email for a in item.to]) # PR_DISPLAY_TO
            # doc['mapi3587'] = u' '.join([a.name + u' ' + a.email for a in item.cc]) # PR_DISPLAY_CC
            # doc['mapi3586'] = u' '.join([a.name + u' ' + a.email for a in item.bcc]) # PR_DISPLAY_BCC
            # doc['data'] = 'subject: %s\n' % item.subject
            # db_put(self.mapping_db, item.sourcekey, '%s %s' % (storeid, item.folder.entryid)) # ICS doesn't remember which store a change belongs to..
            # self.plugin.update(doc)

            #is the document is processed by the spam filter at all?

            if item.header(self.config['header_result'])==None:
                log_str="folder '%s', subject '%s': " % (self.folder.name, item.subject)
                self.log.debug(log_str+"ignored, no spam-headers found")
            else:
                detected_as_spam = ( item.header(self.config['header_result'])==self.config['header_result_spam'] )
                spam_id = item.header(self.config['header_user'])+"-"+item.header(self.config['header_id'])
                retrained = ( db_get(self.retrained_db, spam_id) == "1" )
                in_spamfolder = ( self.folder == self.store.junk )

                log_str="folder: '%s', subject: '%s', spam_id: %s, detected_as_spam: %s, retrained: %s, in_spamfolder: %s, CONCLUSION: " % (self.folder.name, item.subject, spam_id, detected_as_spam, retrained, in_spamfolder)

                # self.log.debug(log_str+"detected as spam: %s, retrained: %s, in spamfolder: %s" % ( detected_as_spam, retrained, in_spamfolder ) )

                if detected_as_spam:
                    if in_spamfolder:
                        if retrained:
                             self.log.debug(log_str+"moved back to spam again: undo training as innocent")
                             db_put(self.retrained_db, spam_id, None)
                        else:
                             self.log.debug(log_str+"spam already in spam folder, no action needed")
                    #in non-spam folder
                    else:
                        if not retrained:
                             self.log.debug(log_str+"moved from spam: retraining as innocent")
                             db_put(self.retrained_db, spam_id, "1")
                        else:
                             self.log.debug(log_str+"moved from spam, already retrained")

                #not detected as spam
                else:
                    if in_spamfolder:
                        if not retrained:
                             self.log.debug(log_str+"moved to spam: retraining as spam")
                             db_put(self.retrained_db, spam_id, "1")
                        else:
                             self.log.debug(log_str+"moved to spam: already retrained")

                    #in non-spam folder
                    else:
                        if retrained:
                             self.log.debug(log_str+"moved from spam again: undo training as spam")
                             db_put(self.retrained_db, spam_id, None)
                        else:
                             self.log.debug(log_str+"normal mail already in normal folder: no action needed")



            # self.term_cache_size += sum(len(v) for k, v in doc.iteritems() if k.startswith('mapi'))
            # if (8*self.term_cache_size) > self.config['term_cache_size']: # XXX profile to fine-tune factor
            #     # self.plugin.commit()
            #     self.term_cache_size = 0

    def delete(self, item, flags):
        """ for a deleted item, determine store and ask indexing plugin to delete """

        with log_exc(self.log):
            self.deletes += 1
            self.log.debug('deleted document with sourcekey %s' % ( item.sourcekey ))
            # ids = db_get(self.mapping_db, item.sourcekey)
            # if ids: # when a 'new' item is deleted right away (spooler?), the 'update' function may not have been called
            #     storeid, folderid = ids.split()
            #     doc = {'serverid': self.serverid, 'storeid': storeid, 'sourcekey': item.sourcekey}
            #     self.log.debug('store %s: deleted document with sourcekey %s' % (doc['storeid'], item.sourcekey))
                # self.plugin.delete(doc)

class IndexWorker(zarafa.Worker):
    """ process which gets folders from input queue and indexes them, putting the nr of changes in output queue """

    def main(self):
        config, server = self.service.config, self.service.server
        state_db = os.path.join(config['index_path'], server.guid+'_state')
        while True:
            changes = 0
            with log_exc(self.log):
                (_, storeguid, folderid, reindex) = self.iqueue.get()
                store = server.store(storeguid)
                folder = zarafa.Folder(store, folderid.decode('hex')) # XXX
                if store.public or folder!=store.outbox:
                    state = db_get(state_db, folder.entryid) if not reindex else None

                    if state:
                        self.log.info('processing changes for folder: %s %s' % (storeguid, folder.name))
                        importer = FolderImporter(server.guid, config, self.log, store, folder)
                        new_state = folder.sync(importer, state, log=self.log)
                        changes = importer.changes + importer.deletes
                    else:
                        self.log.info('new folder, skipping changes so far: %s %s' % (storeguid, folder.name))
                        new_state = folder.state


                    if new_state != state:
                        db_put(state_db, folder.entryid, new_state)
                        # self.log.info('saved folder sync state: %s' % new_state)
                        # self.log.info('syncing folder %s %s took %.2f seconds (%d changes, %d attachments)' % (storeguid, folder.name, time.time()-t0, changes, importer.attachments))

            self.oqueue.put(changes)


class ServerImporter:
    """ tracks changes for a server node; queues encountered folders for updating """

    def __init__(self, serverid, config, iqueue, log):
        # self.mapping_db = os.path.join(config['index_path'], serverid+'_mapping')
        self.log = log
        self.iqueue = iqueue
        self.queued = set() # sync each folder at most once

    def update(self, item, flags):
        if item.folder!=item.store.wastebasket:
            self.queue((0, item.storeid, item.folder.entryid))
        else:
            self.log.debug("ignoring changes in folder: '%s'" % (item.folder.name))


    def delete(self, item, flags):
        pass
        # ids = db_get(self.mapping_db, item.sourcekey)
        # if ids:
        #     self.queue((0,) + tuple(ids.split()))

    def queue(self, folder):
        if folder not in self.queued:
            self.iqueue.put(folder+(False,))
            self.queued.add(folder)

class Service(zarafa.Service):
    """ main search process """

    def main(self):
        """ start initial syncing if no state found. then start query process and switch to incremental syncing """

        self.reindex_queue = Queue()
        index_path = self.config['index_path']
        os.umask(0077)
        if not os.path.exists(index_path):
            os.makedirs(index_path)
        self.state_db = os.path.join(index_path, self.server.guid+'_state')
        # self.plugin = __import__('plugin_%s' % self.config['search_engine']).Plugin(index_path, self.log)
        self.iqueue, self.oqueue = Queue(), Queue()
        self.index_processes = self.config['index_processes']
        workers = [IndexWorker(self, 'index%d'%i, nr=i, iqueue=self.iqueue, oqueue=self.oqueue) for i in range(self.index_processes)]
        for worker in workers:
            worker.start()
        self.state = db_get(self.state_db, 'SERVER')
        if self.state:
            self.log.info('found previous server sync state: %s' % self.state)
        else:
            self.log.info('starting initial sync')
            new_state = self.server.state # syncing will reach at least the current state
            self.initial_sync(self.server.stores())
            self.state = new_state
            db_put(self.state_db, 'SERVER', self.state)
            self.log.info('saved server sync state = %s' % self.state)

        # SearchWorker(self, 'query', reindex_queue=self.reindex_queue).start()
        self.log.info('monitoring mail movements')
        self.incremental_sync()

    def initial_sync(self, stores, reindex=False):
        """ get states of all folders """

        folders = [(f.count, s.guid, f.entryid, reindex) for s in stores for f in s.folders()]
        for f in sorted(folders, reverse=True):
            self.iqueue.put(f)
        itemcount = sum(f[0] for f in folders)
        self.log.info('queued %d folders for initial state discovery' % (len(folders)))
        t0 = time.time()
        changes = sum([self.oqueue.get() for i in range(len(folders))]) # blocking
        self.log.info('queue processed in %.2f seconds (%d changes, ~%.2f/sec)' % (time.time()-t0, changes, changes/(time.time()-t0)))

    def incremental_sync(self):
        """ process changes in real-time (not yet parallelized); if no pending changes handle reindex requests """

        while True:
            with log_exc(self.log):
                try:
                    storeid = self.reindex_queue.get(block=False)
                    self.log.info('handling reindex request for store %s' % storeid)
                    store = self.server.store(storeid)
                    # self.plugin.reindex(self.server.guid, store.guid)
                    self.initial_sync([store], reindex=True)
                except Empty:
                    pass
                importer = ServerImporter(self.server.guid, self.config, self.iqueue, self.log)
                t0 = time.time()
                new_state = self.server.sync(importer, self.state, log=self.log)
                if new_state != self.state:
                    changes = sum([self.oqueue.get() for i in range(len(importer.queued))]) # blocking
                    for f in importer.queued:
                        self.iqueue.put(f+(False,)) # make sure folders are at least synced to new_state
                    changes += sum([self.oqueue.get() for i in range(len(importer.queued))]) # blocking
                    self.log.info('queue processed in %.2f seconds (%d changes, ~%.2f/sec)' % (time.time()-t0, changes, changes/(time.time()-t0)))
                    self.state = new_state
                    db_put(self.state_db, 'SERVER', self.state)
                    self.log.info('saved server sync state = %s' % self.state)
            time.sleep(self.config['process_delay'])

    def reindex(self):
        """ pass usernames/store-ids given on command-line to running search process """

        for key in self.options.reindex: # usernames supported for convenience/backward compatibility
            store = self.server.get_store(key)
            if not store:
                user = self.server.get_user(key)
                if user:
                    store = user.store
            if store: # XXX check all keys first
                with closing(zarafa.client_socket(self.config['server_bind_name'], ssl_cert=self.config['ssl_certificate_file'])) as s:
                    s.sendall('REINDEX %s\r\n' % store.guid)
                    s.recv(1024)
            else:
                print "no such user/store: %s" % key
                sys.exit(1)

def main():
    parser = zarafa.parser('ckpsF') # select common cmd-line options
    parser.add_option('-r', '--reindex', dest='reindex', action='append', default=[], help='Reindex user/store', metavar='USER')
    options, args = parser.parse_args()
    service = Service('search', config=CONFIG, options=options)
    if options.reindex:
        service.reindex()
    else:
        service.start()

if __name__ == '__main__':
    main()
