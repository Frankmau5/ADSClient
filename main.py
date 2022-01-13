import click
from pathlib import Path
from pyADS import ADS
from base64 import b64encode


class DataObj:
    """Dataclass for ADS data"""

    def __init__(self, path, data):
        self.Path = path
        self.Data = data

#TODO: clean up click command to make a nicer cli interface
#TODO: make a nice way to view that data
#TODO: make a way to get data back if you have saved a file


@click.command()
@click.option('--command', help='Command')
@click.option('--path', help='Path to file or folder')
@click.option('--name', help='Name for stream')
@click.option('--data', help='The data you want to add to stream (text or filepath)')
@click.option('--overwrite', default=False, help='Will delete all ADS stream')
def main(path, command, name, data, overwrite):
    app = App()
    if command == "scan":  # scan files for ADS stream
        data = scan_files(path, app=app)
        app.Displayer.basic_print(data)
    elif command == "clear":  # clear metadata in ADS stream
        delete_metadata(path, overwrite, app=app)
    elif command == "add_str":
        add_str_data(path, name, data)
    elif command == "add_file":
        add_bin_data(path, name, data)
    else:
        print(f"{command} command is invalid")


# scan
def scan_files(path, app=None):
    """Scan all files for ADS streams and return list of paths that have them"""
    # todo: make this method work with a file only as well
    if app is None:
        app = App()
    output = list()
    path2 = Path(path)
    for p in path2.rglob("*"):
        if app.is_data_in_file(p):
            output.append(DataObj(p, app.get_data(p)))
    return output


# clear
def delete_metadata(path, overwrite, app=None):
    """After scan_files has been called you can call this to delete metadata in stream e.g Zone.Identifier"""
    if app is None:
        app = App()
    path2 = Path(path)
    for p in path2.rglob("*"):
        if app.is_data_in_file(p):
            app.del_data(p, overwrite)


# add_str_data
def add_str_data(path, name, data_str, app=None):
    """Add string data to a file ASD stream"""
    if app is None:
        app = App()
    r = app.add_str_data(path, name, data_str)
    if r:
        print("data was added.")
    else:
        print("data was not added.")


def add_bin_data(path, name, data_str, app=None):
    """Add bin data to a file ASD stream"""
    if app is None:
        app = App()
    r = app.add_bin_data(path, name, data_str)
    if r:
        print("data was added.")
    else:
        print("data was not added.")


class App:
    """Core ADS Api"""

    def __init__(self):
        self.Displayer = Displayer()

    def is_data_in_file(self, filepath):
        """Searches for ADS steams and return bool"""
        handler = ADS(str(filepath))
        return handler.has_streams()

    def get_data(self, filepath):
        """Get name and data from ADS stream """
        output = list()
        handler = ADS(str(filepath))
        if handler.has_streams():
            for stream in handler:
                d = dict()
                d['Name'] = stream
                d['data'] = handler.get_stream_content(stream)
                output.append(d)
        return output

    def del_data(self, filepath, overwrite=False):
        """Deletes name and data from ASD stream"""
        handler = ADS(str(filepath))
        if handler.has_streams():
            for stream in handler:
                if stream == "Zone.Identifier" or stream == "OECustomProperty" or stream == "encryptable":
                    print(f"Clear ADS in  {filepath}")
                    handler.delete_stream(stream)
                if overwrite:
                    print(f"Clear ADS in  {filepath}")
                    handler.delete_stream(stream)

    def add_str_data(self, filepath, stream_name, str_data):
        """Add string data to ASD stream"""
        handler = ADS(str(filepath))
        b = bytearray()
        b.extend(map(ord, str_data))
        return handler.add_stream_from_string(stream_name, b)

    def add_bin_data(self, filepath, stream_name, file_data):
        """Add binary data to ASD stream by converting data to base64 """
        handler = ADS(str(filepath))
        data = None
        try:
            with open(file_data, mode='rb') as f_open:
                data = f_open.read()
        except FileNotFoundError or FileExistsError:
            print("Error. are you sure this file exist?")
            return False

        if data is not None:
            b64_data = b64encode(data)
            return handler.add_stream_from_string(stream_name, b64_data)
        else:
            return False


class Displayer:
    """command line interface to display data"""
    def __init__(self):
        pass

    def basic_print(self, data):
        '''the most basic way to print DataObj'''
        if type(data) == list:
            for d in data:
                print(f"{d.Path}\n{d.Data}")
                print()
        else:
            print("Error with printing")


if __name__ == "__main__":
    main()
