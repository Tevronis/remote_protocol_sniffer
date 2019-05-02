from io import open


class Writer:

    @staticmethod
    def log_packet(filename, *data):
        if filename:
            # import pdb; pdb.set_trace()
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(' '.join([item.decode('utf-8') for item in data]) + '\n')
        else:
            print ' '.join(data)

    @staticmethod
    def print_spliter(logfile):
        Writer.log_packet(logfile, '\n* * * * * * * * * * * * * * * * *')
