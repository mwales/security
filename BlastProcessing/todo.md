=Blast Processing Todo List=

* After starting and stopping BP runners, if you increase the number of instances, those new
  instances get started even though you already had pressed stop button, now they never die.
* Crashes when stopping QEMU instantes from blast processing
* Hangs forever when trying to stop QEMU instances that have already stopped
* Need better error reporting to user than just qDebug statements and what not
