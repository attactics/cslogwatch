'''
Implements a class used by cslogwatch to hold details of files subject
to state tracking
'''

class FileDetails(object):
    '''
    Class that implements a FileDetails object. This object stores a
    file path as well as the number of lines in the file
    '''

    filepath = ""
    lines = 0

    def set_filepath(self, filepath):
        ''' Sets the filepath parameter of the FileDetails object '''
        self.filepath = filepath

    def get_filepath(self):
        ''' Gets the filepath parameter of the FileDetails object '''
        return self.filepath

    def get_line_count(self):
        ''' Gets the line count parameter of the FileDetails object '''
        return self.lines

    def set_line_count(self, lines):
        ''' Sets the line count parameter of the FileDetails object '''
        self.lines = lines

    def to_dict(self):
        ''' Returns a dict of the FileDetails object '''
        return {"filepath": self.filepath, "lines": self.lines}
