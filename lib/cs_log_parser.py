'''
Implements a class used by cslogwatch to hold parse cobalt strikg log files
'''

import datetime
import re
from termcolor import colored
from dateutil import parser
import cs_log_entry

class CSLogParser(object):
    ''' Implements various functionality required to successfully parse Cobalt Strike log fils'''

    def create_cs_log_item(self, cs_log_item):
        ''' creates and returns a CSLogEntry object containing the supplied input values '''
        cslog = cs_log_entry.CSLogEntry()
        cslog.set_timestamp(cs_log_item['timestamp'])
        cslog.set_content(cs_log_item['content'])
        cslog.set_ip_address(cs_log_item['ip_address'])
        cslog.set_computer(cs_log_item['computer_name'])
        cslog.set_pid(cs_log_item['pid'])
        cslog.set_username(cs_log_item['username'])
        cslog.set_event_type(cs_log_item['type'])
        return cslog

    def parse_log_format(self, line):
        ''' Parses a Cobalt Strike log line and extracts attributes '''
        line = line.replace("\n", "")
        split_line = line.split(" ")
        # if the line splits in to 2 or less strings, we know it's not a valid
        # log entry line immediately
        if len(split_line) > 2:
            # Check various line areas to confirm we are dealing with a log entry
            date = split_line[0]
            is_date = self.check_date(date)
            time = split_line[1]
            is_time = self.check_time(time)
            utc = split_line[2]
            is_utc = self.check_utc(utc)
            # if URC is present in the line, all values will shift in index
            # here we ensure that we account for that and parse appopriately
            if is_utc:
                event_type = split_line[3]
                is_type = self.check_event_type(event_type)
                content = ' '.join(split_line[4:])
            else:
                event_type = split_line[2]
                is_type = self.check_event_type(event_type)
                content = ' '.join(split_line[3:])

            # trim square brackets from event_type
            event_type = event_type.replace('[', '')
            event_type = event_type.replace(']', '')
            regex = re.compile('[^a-zA-Z]')
            event_type = regex.sub('', event_type)
            # Pass all the data back

            return  is_date, date, is_time, time, is_type, event_type, content
        else:
            # The line was split to 2 or less values, we know this cannot be a log entry line
            # and so we return all values as Nonetype
            return None, None, None, None, None, None, None


    def get_file_metadata(self, filepath):
        ''' Returns the cobalt strike log entry metadata for the file path provided '''
        metadata_lines = []
        with open(filepath) as log:
            for line in log:
                if "[metadata]" in line:
                    metadata_lines.append(line)
        if len(metadata_lines) != 0:
            metadata = metadata_lines[-1]
            split_line = metadata.split(" ")
            date = split_line[0]
            is_date = self.check_date(date)
            time = split_line[1]
            is_time = self.check_time(time)
            utc = split_line[2]
            is_utc = self.check_utc(utc)
            if is_date and is_time:
                if is_utc:
                    log_ip_address = split_line[4]
                    log_computer_name = split_line[8].replace(";", "")
                    log_username = split_line[10].replace(";", "")
                    log_pid = split_line[12].replace(";", "")
                else:
                    log_ip_address = split_line[3]
                    log_computer_name = split_line[7].replace(";", "")
                    log_username = split_line[9].replace(";", "")
                    log_pid = split_line[11].replace(";", "")
                return log_ip_address, log_computer_name, log_username, log_pid
        else:
            return 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN'

    def parse(self, filepath, start_line=0, end_line=0):
        '''
        Iterates through all or a range of a specified file and parses cobalt strike
        log entry contents
        '''

        previous_type_was_output = False
        output_event_content = ""
        log_ip_address = None
        log_computer_name = None
        log_username = None
        log_pid = None
        cs_log_entries = []
        line_number = 0
        num_lines_in_file = self.get_num_lines(filepath)
        partial_file_process = False
        if start_line != 0 and end_line != 0:
            partial_file_process = True
        with open(filepath) as log:
            for line in log:
                line_number += 1
                if line == "" or line == "\n" or line =="\r\n":
                    continue
                if partial_file_process:
                    # If we are below our target start line we continue to the next iteration
                    if line_number < start_line:
                        continue
                    # If we are above our target end line we continue to the next iteration
                    elif line_number > end_line:
                        continue
                is_date, date, is_time, time, is_type, event_type, content = \
                self.parse_log_format(line)
                if is_date and is_time and is_type:
                    if previous_type_was_output:
                        timestamp = self.prepare_timestamp_to_string(date, time)
                        if output_event_content == "":
                            output_event_content = "None"
                        try:
                            # Retrieve metadata for database entry
                            log_ip_address, log_computer_name, log_username, log_pid = \
                            self.get_file_metadata(filepath)

                            # log output from previous command (previous lines)
                            cs_log_item = {'timestamp' : output_event_timestamp,
                                           'content' : output_event_content,
                                           'ip_address' : log_ip_address,
                                           'computer_name' : log_computer_name,
                                           'pid' : log_pid,
                                           'username' : log_username,
                                           'type' : 'output'}
                            cslog = self.create_cs_log_item(cs_log_item)
                            cs_log_entries.append(cslog)
                            # log current line
                            cs_log_item = {'timestamp' : timestamp,
                                           'content' : content,
                                           'ip_address' : log_ip_address,
                                           'computer_name' : log_computer_name,
                                           'pid' : log_pid,
                                           'username' : log_username,
                                           'type' : event_type}
                            cslog = self.create_cs_log_item(cs_log_item)
                            cs_log_entries.append(cslog)
                        except Exception as exception:
                            print(colored('[ERROR] - SQL - '+ str(exception), 'red'))
                        # Output event is written to CSLogEntry object, here we clear the values
                        # for next use
                        output_event_timestamp = ""
                        output_event_content = ""
                        previous_type_was_output = False
                    else:
                        # This is kind of janky - sometimes trailing data
                        if event_type == "output":
                            previous_type_was_output = True
                            output_event_timestamp = self.prepare_timestamp_to_string(date, time)
                            continue
                        try:
                            timestamp = self.prepare_timestamp_to_string(date, time)
                            # Retrieve metadata for database entry
                            log_ip_address, log_computer_name, log_username, log_pid = \
                            self.get_file_metadata(filepath)
                            cs_log_item = {'timestamp' : timestamp,
                                           'content' : content,
                                           'ip_address' : log_ip_address,
                                           'computer_name' : log_computer_name,
                                           'pid' : log_pid,
                                           'username' : log_username,
                                           'type' : event_type}
                            cslog = self.create_cs_log_item(cs_log_item)
                            cs_log_entries.append(cslog)
                        except Exception as exception:
                            print(colored('[ERROR] - SQL - '+ str(exception), 'red'))
                else:
                    if previous_type_was_output:
                        # If we aren't in the last line of the file, we continue appending each
                        # line to the output. When we iterate over the next line, if it is a
                        # new event_type we will know to write the aggregate output and the new line
                        if line_number != num_lines_in_file:
                            output_event_content = output_event_content + line
                            continue
                        # We are in the last line of the file, so we need to write the output
                        # as there will not be a subsequent event to trigger the write
                        else:
                            # Retrieve metadata for database entry
                            log_ip_address, log_computer_name, log_username, log_pid = \
                            self.get_file_metadata(filepath)
                            cs_log_item = {'timestamp' : output_event_timestamp,
                                           'content' : output_event_content,
                                           'ip_address' : log_ip_address,
                                           'computer_name' : log_computer_name,
                                           'pid' : log_pid,
                                           'username' : log_username,
                                           'type' : 'output'}
                            cslog = self.create_cs_log_item(cs_log_item)
                            cs_log_entries.append(cslog)
                            continue
                    else:
                        print(colored('[ERROR] - UNKNOWN LINE IN ' + filepath + ' @ line ' + \
                        str(line_number), 'red'))
                        print(line)
                        exit()
                        break
        return cs_log_entries
        #for log in cs_log_entries:
        #    self.write_log_to_db(log)

    def check_date(self, input_text):
        ''' Checks whether the supplied string confirms to a MM/DD date '''
        try:
            datetime.datetime.strptime(input_text, '%m/%d')
            return True
        except ValueError:
            return False

    def check_time(self, input_text):
        ''' Checks whether the supplied string confirms to a H:M:S timestamp '''
        try:
            datetime.datetime.strptime(input_text, '%H:%M:%S')
            return True
        except ValueError:
            return False

    def check_utc(self, input_text):
        ''' Checks whether the supplied string contains 'UTC' '''
        if input_text == "UTC":
            return True
        return False

    def check_event_type(self, input_text):
        '''
        Checks whether the supplied string contains a substring that looks like a cobalt
        strike event type
        '''
        input_type = re.search(r'\[(.*?)\]', input_text)
        if input_type is not None:
            return True
        return False

    def get_num_lines(self, filepath):
        ''' Counts the number of lines in the input file '''
        i = 0
        with open(filepath) as file:
            for line in file:
                i += 1
        return i

    def prepare_timestamp(self, date, time):
        ''' Creates datetime timestamp object from supplied input date and time strings '''
        day_month = date.split('/')
        timestamp = "2019-"+day_month[0]+"-"+day_month[1]+" " + time + " UTC"
        result = parser.parse(timestamp)
        #result = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S", tzinfo=pytz.UTC)
        return result

    def prepare_timestamp_to_string(self, date, time):
        ''' Creates datetimeobject compatible string from supplied input date and time strings '''
        day_month = date.split('/')
        timestamp = "2019-"+day_month[0]+"-"+day_month[1]+" " + time + " UTC"
        return timestamp
