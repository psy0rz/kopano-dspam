Kopano realtime spam retraining.

Difference with the normal kopano-spamd:

 * It runs a script instead of creating mails in a folder.
 * Can also untrain when you undo a move.
 * Has better logging.
 * Configurable spam-header so it can be used for all kinds of 3rd party spam systems.


Example logging output: 
```
2018-08-03 11:06:19,663 - dspam - INFO - spam_user: psy, folder: 'Inbox', subject: 'Got High Blood Pressure? Then Don???t Take THIS (Increases Stroke Risk by 248%)', spam_id: 5a1f2c2f68521785918732, detected_as_spam: True, retrained: False, in_spamfolder: False, CONCLUSION: moved from spam: retraining as innocent
2018-08-03 11:06:19,669 - dspam - DEBUG - Starting: [u'/etc/kopano/userscripts/kopano-dspam-retrain', 'psy', '5a1f2c2f68521785918732', 'innocent', '']
2018-08-03 11:06:19,735 - dspam - DEBUG - Command exited with code 0
```
 
We created this plugin for our own Linux distribution which can be found on https://www.syn-3.eu.
