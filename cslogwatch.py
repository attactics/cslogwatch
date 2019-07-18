'''
cslogwatch is a tool that monitors a defined directory of cobalt stike log files for additions,
modification and deletions. It will parse any cobalt strike related data within the log files
and store the entries in an sqlite3 database. cslogwatch writes monitoring states to disk; if
it crashes or the process otherwise becomes unresponsive, it is capable of determining the
delta between present and past states and then parsing and storing the new content in the
database
'''

import time
import json
import os
import sqlite3
from sqlite3 import Error
import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from termcolor import colored
from dateutil import parser
from lib import cs_log_parser
from lib import cs_file_details

class Watcher(object):
    '''
    responsible for establishing an Observer instance to monitor for file changes
    and invoke the appropriate handler
    '''
    watch_dir = ""

    def __init__(self, directory):
        self.observer = Observer()
        self.watch_dir = directory

    def run(self):
        '''
        initiate a loop that will monitor for any file changes within the specified
        directory. we define the Handler class as our event handler
        '''
        event_handler = Handler()
        self.observer.schedule(event_handler, self.watch_dir, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except Exception as exception:
            self.observer.stop()
            print exception

        self.observer.join()



class Handler(FileSystemEventHandler):
    ''' Responsible for handling events sent from the Watchdog observer instance '''
    @staticmethod
    def on_any_event(event):
        # Ignore directories
        if event.is_directory:
            return None
        # File creation event
        elif event.event_type == 'created':
            # Take any action here when a file is first created.
            print colored('[FILE] (+) - ' + event.src_path, 'green')
            input_file = open(event.src_path, 'r')
            i = 0
            for line in input_file:
                i += 1
            input_file.close()
            STATE_MAPPER.add_file_and_parse(event.src_path, i, True)

        # File modified event
        elif event.event_type == 'modified':
            # Open the file and count the number of lines
            log_file = open(event.src_path, 'r')
            current_line_count = 0
            for line in log_file:
                current_line_count += 1
            log_file.close()
            # Retrievee existing file information
            input_file = STATE_MAPPER.get_file(event.src_path)
            # We increment the original line count by 1 as we want to start with the first new line
            original_line_count = input_file.get_line_count()
            # Delta lines added to file
            line_delta = current_line_count - original_line_count
            # Update the FileMapper instance to new line count and process changes
            # We increment the original line count by 1 as we want to start with the first new line
            STATE_MAPPER.update_file(event.src_path, current_line_count+1, original_line_count, True)
            print colored('[FILE] (%) - ' + event.src_path + ' ('+str(line_delta)+' lines)', 'yellow')

        # File deleted event
        elif event.event_type == 'deleted':
            print colored('[FILE] (-) - ' + event.src_path, 'red')
            # Update FileMapper instance to remove file and update state
            STATE_MAPPER.delete_file(event.src_path, True)


class StateMapper(object):
    '''
    Responsible for file state mapping. It implements logic to handle file statese management
    upon creation, addition, and deletion of files from the monitored directory
    '''
    name = ""
    directory = ""
    database = ""
    fileList = []
    cslp = cs_log_parser.CSLogParser()


    def __init__(self, name, directory, database):
        self.name = name
        self.directory = directory
        self.database = database
        self.enumerate_files()

    def set_dir(self, path):
        ''' Sets the target directory name '''
        self.directory = path

    def get_dir(self):
        ''' Gets the target directory name '''
        return self.directory

    def set_database(self, db_path):
        ''' Sets the database path '''
        self.database = db_path

    def get_database(self):
        ''' Gets the database path '''
        return self.database

    def get_file(self, filepath):
        ''' Gets a specific monitore log file '''
        for log_file in self.fileList:
            if log_file.get_filepath() == filepath:
                return log_file
        return None


    def add_file(self, path, lines, write_state):
        '''
        Adds a file to the current set of tracked files but does not parse the file
        This function is used to build a current state upon initialization
        '''
        x = cs_file_details.FileDetails()
        x.set_filepath(path)
        x.set_line_count(lines)
        self.fileList.append(x)
        if write_state:
            self.write_state()

    def add_file_and_parse(self, path, lines, write_state):
        ''' Adds a file to the current set of tracked files and parses the file '''
        x = cs_file_details.FileDetails()
        x.set_filepath(path)
        x.set_line_count(lines)
        self.fileList.append(x)
        cs_log_entries = self.cslp.parse(path)
        for item in cs_log_entries:
            self.write_log_to_db(item)
        if write_state:
            self.write_state()

    def delete_file(self, filepath, write_state):
        ''' Removes the specified file from state tracking '''
        for log_file in self.fileList:
            if log_file.get_filepath() == filepath:
                self.fileList.remove(log_file)
        if write_state:
            self.write_state()

    def update_file(self, name, current_line_count, original_line_count, write_state):
        ''' Updates line count of a tracked file and parses the file '''
        for log_file in self.fileList:
            if log_file.get_filepath() == name:
                log_file.set_line_count(current_line_count)
                # We add one so that the parsing happens after the last previously existing line
                cs_log_entries = self.cslp.parse(name, original_line_count+1, current_line_count)
                for item in cs_log_entries:
                    self.write_log_to_db(item)
                if write_state:
                    self.write_state()

    def get_files(self):
        ''' Returns all tracked files as a list of FileDetails objects '''
        return self.fileList

    def write_state(self):
        ''' Writes the current in-memory tracking state to disk '''
        results = [obj.to_dict() for obj in self.get_files()]
        jsdata = json.dumps({'name' : self.name, 'directory' : self.get_dir(), 'files' : results}, \
            indent=4, sort_keys=True)
        state_file = open(self.name +'.cslogwatchstate', 'w')
        state_file.write(jsdata + '\n')
        state_file.close()

    def get_sql_project_id(self):
        ''' Retrieves the UID of a project from the database '''
        conn = sqlite3.connect(self.database)
        sql = conn.cursor()
        row = None
        try:
            #    cur.execute("SELECT * FROM tasks WHERE priority=?", (priority,))
            sql.execute("SELECT id FROM project WHERE name=?", (self.name,))
            row = sql.fetchone()
        except Exception as exception:
            print(colored('[ERROR] - SQL - '+ str(exception), 'red'))
        conn.commit()
        conn.close()
        if row is not None:
            return row[0]
        return None

    def create_project_id(self):
        ''' Creates a row in the project table for a new project '''
        conn = sqlite3.connect(self.database)
        sql = conn.cursor()
        row = None
        try:
            sql.execute("INSERT INTO project (name) VALUES (?)", (self.name,))
            sql.execute("SELECT id FROM project WHERE name=?", (self.name,))
            row = sql.fetchone()
        except Exception as exception:
            print(colored('[ERROR] - SQL - '+ str(exception), 'red'))
        conn.commit()
        conn.close()
        if row is not None:
            return row[0]
        return None

    def write_log_to_db(self, log):
        ''' Takes a CSLogEntry object and stores it in the sqlite database '''

        # Get the project ID for specifying foreing key relationship on row
        project_id = self.get_sql_project_id()
        # If the project ID was not found, it is a new project and needs to be created
        if project_id is None:
            project_id = self.create_project_id()
        # Open DB connectio nand initialize cursor
        conn = sqlite3.connect(self.database)
        sql = conn.cursor()
        try:
            # Check to see if the system related to the log entry already exists in the
            # system table for this specific project
            sql.execute("SELECT * FROM system WHERE name=? AND project_id=?", \
                (log.get_computer(), project_id))
            row = sql.fetchone()
            if row is None:
                # The system does not exist, so it is inserted in to the system table
                sql.execute("INSERT INTO system (name, project_id) VALUES(?,?)", \
                (log.get_computer(), project_id))
            # Insert the cobalt strike log entry in to the event table
            sql.execute('''INSERT INTO event (timestamp, eventType, content, computer, \
                ipAddress, pid, username, project_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', \
                                                             (parser.parse(log.get_timestamp()),
                                                              log.get_event_type(),
                                                              log.get_content(),
                                                              log.get_computer(),
                                                              log.get_ip_address(),
                                                              log.get_pid(),
                                                              log.get_username(),
                                                              project_id))
        except sqlite3.IntegrityError as e:
            # We ignore IntegrityErrors as this is usually due to duplicate log entries existing in
            # the log data. While this doesn't normally happen, it can happen in the event that
            # unknown beacons are logged. To keep the output quiet, we pass on handling this
            # exception.
            pass
        except Exception as exception:
            print(colored('[ERROR] - SQL - '+ str(exception), 'red'))
        # Commit changes & close DB connection
        conn.commit()
        conn.close()

    def enumerate_files(self):
        '''
        Walks the specified directory within the FileMapper object to identify
        all files that end in .log while ignoring events.log, weblog.log and download.log
        '''
        for root, dirs, files in os.walk(self.get_dir()):
            for filename in files:
                if filename.endswith(".log") and filename != "events.log" and filename != "weblog.log" \
                and filename != "downloads.log":
                    # Count the number of lines in the file
                    with open(os.path.join(root, filename)) as log:
                        i = 0
                        for line in log:
                            i += 1
                    # Add the file to the current state but do not parse it
                    self.add_file(os.path.join(root, filename), i, False)
        # Compare the newly collected state to the state written on disk
        self.compare_state()
        # Write the new state to disk
        self.write_state()

    def compare_state(self):
        '''
        Compares the on-disk file state of monitored directory to the present state
        Used to parse any changes made to files since cslogwatch was last running
        '''
        state_list_file_paths = None
        print colored("[INIT] - Running cached to present state comparison", 'green')
        # Try to open state file for this specific project
        try:
            state_file = open(self.name +'.cslogwatchstate', 'r')
        except:
            state_file = None
            print colored("[INIT] - State file not found!", 'red')
            print colored("[INIT] - Building new state file", 'yellow')
        # If we found a state file, process it
        if state_file is not None:
            data = json.load(state_file)
            state_file.close()
            state_list = []

            # Populate state_list list with FileDetails object instances from state file
            for state_file in data['files']:
                file_details_object = cs_file_details.FileDetails()
                file_details_object.set_filepath(state_file['filepath'])
                file_details_object.set_line_count(state_file['lines'])
                state_list.append(file_details_object)

            # Enumerate all FilePaths found in statefile
            state_list_file_paths = []
            for state_file in state_list:
                state_list_file_paths.append(state_file.get_filepath())

        # Check for the presence of new files not in state list
        # as well as changes to files in state list
        for log_file in self.fileList:
            file_path = log_file.get_filepath()
            filelines = log_file.get_line_count()
            if state_list_file_paths is None:
                print colored("[INIT] - (+) FILE - " + log_file.get_filepath(), 'green')
                cs_log_entries = self.cslp.parse(log_file.get_filepath())
                for log in cs_log_entries:
                    self.write_log_to_db(log)
                #self.parse(f.get_filepath())
            elif file_path not in state_list_file_paths or not state_list_file_paths:
                print colored("[INIT] - (+) FILE - " + log_file.get_filepath(), 'green')
                cs_log_entries = self.cslp.parse(log_file.get_filepath())
                for log in cs_log_entries:
                    self.write_log_to_db(log)
            else:
                for state_file in state_list:
                    if file_path == state_file.get_filepath():
                        line_delta = filelines - state_file.get_line_count()
                        if line_delta > 0:
                            print colored("[INIT] - (%) FILE " + file_path + " | ", 'yellow') \
                                + colored("+" +str(line_delta) +  " lines", 'green')

        # Check for the deletion of files cached in statelist
        if state_list_file_paths is not None:
            for state_file in state_list:
                res = next((x for x in self.fileList if x.get_filepath() == \
                    state_file.get_filepath()), None)
                if not res:
                    file_path = state_file.get_filepath()
                    print colored("[INIT] - (-) FILE - " + file_path, 'red')
        print colored('[INIT] - Complete', 'green')

def show_banner():
    ''' shows a lame banner '''

    print (colored('''
          _                           _       _     
  ___ ___| | ___   __ ___      ____ _| |_ ___| |__  
 / __/ __| |/ _ \ / _` \ \ /\ / / _` | __/ __| '_ \ 
| (__\__ \ | (_) | (_| |\ V  V / (_| | || (__| | | |
 \___|___/_|\___/ \__, | \_/\_/ \__,_|\__\___|_| |_|
                  |___/    attactics.org        v1.0
        ''', 'green'))

def parse_config():
    ''' Parses cslowgwatch config.yaml to retrieve required operating parameters '''
    with open("config.yaml", 'r') as config:
        try:
            config_data = yaml.safe_load(config)
        except yaml.YAMLError as exc:
            print colored('[ERROR] - Invalid config.yaml', 'red')
    return config_data

def check_db_exists(path):
    ''' Chekcs whether or not the specified database file exists '''
    if os.path.exists(path):
        return True
    return False

def get_file_contents(path):
    ''' Retrieves the contents of the specified file path '''
    with open(path, 'r') as input_file:
        try:
            contents = input_file.read()
        except Exception as exception:
            print(colored('[ERROR] - Unable to read SQL table / index definition', 'red'))
            exit()
    return contents

def retrieve_db_table_statements():
    ''' Retrieves table creation & index statements and returns a dict containing the same '''
    sql_queries = {}
    sql_queries['project'] = get_file_contents('sql/project.sql')
    sql_queries['system'] = get_file_contents('sql/system.sql')
    sql_queries['event'] = get_file_contents('sql/event.sql')
    sql_queries['event_project_id_index'] = get_file_contents('sql/event_project_id_index.sql')
    sql_queries['system_project_id_index'] = get_file_contents('sql/system_project_id_index.sql')
    sql_queries['event_unique_index'] = get_file_contents('sql/event_unique_index.sql')
    return sql_queries

def create_new_db(db_path):
    ''' creates new cslogwatch database if the specified one was not found '''
    try:
        conn = sqlite3.connect(db_path)
        sql = conn.cursor()
        sql_queries = retrieve_db_table_statements()
        sql.execute(sql_queries['project'])
        sql.execute(sql_queries['system'])
        sql.execute(sql_queries['event'])
        sql.execute(sql_queries['event_project_id_index'])
        sql.execute(sql_queries['system_project_id_index'])
        sql.execute(sql_queries['event_unique_index'])
        conn.commit()
        conn.close()
    except Error as exception:
        print(colored('[ERROR] - Unable to create new database database ('+db_path+')', 'red'))
        exit()
    finally:
        conn.close()

if __name__ == '__main__':
    show_banner()
    # parse config.yaml to retrieved required operational parameters
    config_data = parse_config()
    db_exists = check_db_exists(config_data['database'])
    if not db_exists:
        create_new_db(config_data['database'])
    if not os.path.exists(config_data['monitored_directory']):
        print(colored('[ERROR] - Target monitoring directory not found ('+config_data['monitored_directory']+')', 'red'))
        exit()
    # Initialize Watcher and FileMapper objects
    FILE_WATCHER = Watcher(config_data['monitored_directory'])
    STATE_MAPPER = StateMapper(config_data['project_name'], config_data['monitored_directory'], config_data['database'])
    #enumerate_files(STATE_MAPPER)
    # Begin watching for file changes
    print colored('[MONITOR] - File monitoring started', 'green')
    FILE_WATCHER.run()
