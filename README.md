# cslogwatch

v1.0

## What does it do?
cslogwatch is python-based application that implements log watching, parsing, and storage functionality. It is capable of state tracking any cobalt strike log directory and monitoring for any file creations, modifications, or deletions. Once cslogwatch identifies a new log file creation or existing file modification, the log files are automatically parsed and the results are stored in an sqlite database. 

## Features
- Reasonably robust (beta) parsing capabilities that include handling of log files without metadata as well as log files that end in output streams
- Constraints placed on the database ensure that duplicate log entries are not committed to the database
- Resilience to unexpected process hanging or termination. By maintaining an on-disk state file, cslogwatch will compare what it found during initialiation to the last saved mapping state. Any delta is automatically parsed and stored in the sqlite3 database. This implies that you can execute an entire exercise without cslogwatch and import all of your data at the end.

## Parser Library
cslogwatch implements all parsing functionality within modules. You can easily and quickly retool this library for use with your custom code. The library already includes the ability to export log entry items in both python `dict` and`json` formats.

## How do I use it?
cslogwatch is straightforward to get up and running. First you need to install cslogwatch's requirements:

```bash
	pip -r install requirements.txt
```

Next you need to edit the `config.yaml` file to specify the following:
- `database`: relative path to the cslogwatch database. If one does not exist at the specified path, it will be automatically created by cslogwatch.
- `project_name`: This is the name of the project. Generally this would be tied to the red team exercis as all log entries will 'belong' (via foreign key) to this project
- `monitored_directory` : This is the Cobalt Strike log file directory to be monitored by cslogwatch

Execute cslogwatch:

```bash
	python cslogwatch.py
```

The first time cslogwatch runs it will create a new sqlite database if one of the specified name does not already exist. The default directory to be monitored will be `logs/` .

## TODO

- Rewrite the session metadata lookup functionality to find the last metadata entry before the current line being parsed
  - Although session metadata should appear only once in a beacon log file, it is not impossible for it to appear multiple times, as such the most accurate session metadata data would be the last instance before line being parsed
- Write more robust UTC timezone detection 
- Implement cslogwatch stdout output to log file
  - For the time being the output can manually be redirected 
