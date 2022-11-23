cbak - Cloud Backups
====================

This is a small program to create zlib-compressed, AES256-encrypted backups to
Google Drive. Storage space across multiple accounts is consolidated and files
are managed in chunks. File chunk hashes are stored and only those chunks whose
hashes change are transferred. Versioned backups are supported through Google Drive's
revision history system. This means that all but the most recent backup are
automatically kept for a limited time but the most recent backup is permanant.



## Installing

To install a binary, see [releases](https://github.com/0xsx/cbak/releases). To build from source, see here:

#### Requirements

* Python 3
* [pycrypto](https://pypi.org/project/pycrypto/) / [pycryptodome](https://pypi.org/project/pycryptodome/) (if running the Python script)
* [pycurl](http://pycurl.io/) (if running the Python script)
* pyinstaller (to build standalone executable)


#### Building

    pyinstaller -F cbak.py



## Usage


#### Google drive API access

To access the Google Drive API for an account, each file to be managed must be associated with
an OAuth Client ID. Create each ID as follows:

1. Login to the [Google API Console](https://console.developers.google.com/apis/credentials) and create a new project.

2. Go to the Dashboard, select ENABLE APIS AND SERVICES, and enable the Google Drive API.

3. Click CREATE CREDENTIALS and create an OAuth Client ID. Configure the consent screen as required. For Application type choose Other.

4. Copy the Client ID and Client Secret to the manifest file.

Multiple files can have the same client ID and secret, but files must have unique
names to prevent being overwritten.


#### The manifest file

The program uses a manifest file to know which accounts and files to manage. The
manifest file must be provided by the user. If no manifest file is specified at
runtime, the program tries to read one in the current working directory. Each manifest
should be stored in a secured location as it contains the passphrase and key salt
used to encrypt content.

Here is an example manifest file:

    {
      "tag": "Backup Storage",      // Must be unique.
      "max_chunk_size": 6291456,    // In bytes. Pre-compression.

      "passphrase": "",             // For creating the AES secret key.
      "key_salt": "",               // For salting the passphrase.

      "files": [                    // Populate as needed.
        {
          "name": "0.img",
          "client_id": "",
          "client_secret": ""
        }
      ]
    }


The manifest must contain an array associating files to client account IDs.
For example,

    "files": [
        {
          "name": "0.img",
          "client_id": "ID0",
          "client_secret": "SECRET0"
        },

        {
          "name": "1.img",
          "client_id": "ID1",
          "client_secret": "SECRET1"
        }
      ]


tells the program to manage the file "0.img" using client id `ID0` and the file
"1.img" using client id `ID1`. Replace these as needed.


#### Granting app permission

The first time connecting to storage requires granting permission for the app
to access the client ID. Permissions are remembered after the first time
allowing access. The first time the app connects, it will prompt for an
authorization code. Go to the provided URL, login as the associated account,
and allow access to the app. Then copy the authorization code back into the program.
Upon successful connection the program will produce a `.token` file remembering
authorization for subsequent connections. This file must remain in the same
directory as the manifest.



#### Avoiding naming problems

File chunks are named and referenced on the server by SHA256 hashes. If two chunks
have the same name, they will overwrite each other. Similarly, if a chunk is
uploaded and some parameters change in the manifest, the chunk will have to
be re-uploaded before it can be downloaded correctly. The chunk name is determined
by hashing the concatenation of the tag, secret key, max chunk size, the
name of the file exactly as specified in the manifest, and the chunk index in
the file. This means that if any of the the parameters in the manifest change
after upload aside from the client id and secret, the program will try to reference
file chunks that are different from what was uploaded. For example, if a file
name changes from relative path to absolute path, the server will look for
different files, even if the name references the same file on the local filesystem.




## Contributing

If you would like to contribute source code, please submit a
pull request for any open issue.




## Disclaimer

This project is not supported by or associated with Google or any of
its projects. It is only a program that uses the public Google Drive API.


## License

GPLv3.



