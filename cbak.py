#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Manages uploading and downloading encrypted backups to/from cloud storage.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function


import binascii
import hashlib
import hmac
import json
import math
import multiprocessing
import os
import pycurl
import sys
import traceback
import zlib

try:
  import Queue as queue
except ImportError:
  import queue


try:
  import urllib.parse
  url_escape = urllib.parse.quote
except ImportError:
  import urllib
  url_escape = urllib.quote


from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
  
from io import BytesIO
from random import shuffle
from time import sleep, time



COMPRESSION_LEVEL = 5
CONNECT_TIMEOUT = 60
EXPIRE_THRESHOLD = 90
MAX_UPLOAD_RETRIES = 5
PROGRESS_SLEEP_TIME = 0.1

ACCESS_TOKEN_URL = "https://accounts.google.com/o/oauth2/v2/auth"
AUTH_URI = "https://www.googleapis.com/oauth2/v4/token"
FILES_URI = "https://www.googleapis.com/drive/v3/files"
UPLOAD_URI = "https://www.googleapis.com/upload/drive/v3/files"




def print_usage():
  """Prints the formatted usage text to standard output."""
  
  name = os.path.splitext(os.path.basename(__file__))[0]

  sys.stdout.write("\nManage encrypted backups to Google drive.\n\n")

  sys.stdout.write("USAGE:\n\n")
  sys.stdout.write("    \033[1m%s up \033[0m [\033[4mmanifest_file\033[0m]" % name)
  sys.stdout.write("    Upload to cloud storage the data defined in\n")
  sys.stdout.write("                                ")
  sys.stdout.write("the JSON file \033[4mmanifest_file\033[0m. Replaces the\n")
  sys.stdout.write("                                ")
  sys.stdout.write("current version on the server of any data\n")
  sys.stdout.write("                                ")
  sys.stdout.write("having the tag specified in that file.\n\n")

  sys.stdout.write("    \033[1m%s down [-f]\033[0m [\033[4mmanifest_file\033[0m [\033[4mrevision\033[0m]]\n" % name)
  sys.stdout.write("                                ")
  sys.stdout.write("Download from cloud storage the uploaded\n")
  sys.stdout.write("                                ")
  sys.stdout.write("data specified in \033[4mmanifest_file\033[0m.\n")
  sys.stdout.write("                                ")
  sys.stdout.write("If \033[4mrevision\033[0m is specified, it selects the\n")
  sys.stdout.write("                                ")
  sys.stdout.write("revision before the latest to download.\n")
  sys.stdout.write("                                ")
  sys.stdout.write("Defaults to 0. If the \033[1m-f\033[0m flag is not given\n")
  sys.stdout.write("                                ")
  sys.stdout.write("then any download conflicts raise an error.\n\n")

  sys.stdout.write("If not specified, \033[4mmanifest_file\033[0m defaults to ")
  sys.stdout.write("manifest.json in the current \nworking directory.\n\n")





def parse_args():
  """Parses command line arguments and returns the selected action and arguments."""

  cwd = os.path.realpath(os.getcwd())

  if len(sys.argv) < 2:
    print_usage()
    sys.exit(1)

  try:
    action = str(sys.argv[1]).lower()
  except:
    print_usage()
    sys.exit(1)

  if action == "up":
    if len(sys.argv) < 3:
      manifest_file = os.path.join(cwd, "manifest.json")
    elif len(sys.argv) == 3:
      try:
        manifest_file = os.path.realpath(sys.argv[2])
      except:
        print_usage()
        sys.exit(1)
    else:
      print_usage()
      sys.exit(1)

    ret_args = (manifest_file,)


  elif action == "down":
    if len(sys.argv) < 3:
      args = []
      force_overwrite = False
    elif sys.argv[2] == "-f":
      force_overwrite = True
      args = sys.argv[3:]
    else:
      force_overwrite = False
      args = sys.argv[2:]

    if len(args) == 0:
      manifest_file = os.path.join(cwd, "manifest.json")
      revision = 0
    else:
      manifest_file = os.path.realpath(args[0])
      revision = 0
      if len(args) > 1:
        try:
          revision = int(args[1])
        except:
          print_usage()
          sys.exit(1)

      if len(args) > 2:
        print_usage()
        sys.exit(1)

    ret_args = (manifest_file, revision, force_overwrite)

  else:
    print_usage()
    sys.exit(1)


  return action, ret_args








def read_manifest_file(manifest_file):
  """Reads manifest parameters from the specified JSON file."""

  # Strip comments while keeping line numbers.
  manifest_str = ""
  with open(manifest_file, "r") as f_in:
    for line in f_in:
      line = line.rstrip()
      comment_pos = line.find("//")
      if comment_pos > -1:
        line = line[:comment_pos]
      manifest_str += line + "\n"

  manifest = json.loads(manifest_str)


  tag = str(manifest["tag"])
  max_chunk_size = int(manifest["max_chunk_size"])
  passphrase = str(manifest["passphrase"])
  salt = str(manifest["key_salt"])


  # Get list of files relative to manifest file location.
  os.chdir(os.path.dirname(manifest_file))

  file_tups = []
  for obj in manifest["files"]:
    data_file = os.path.realpath(obj["name"])
    file_tups.append((data_file, obj["name"], str(obj["client_id"]), str(obj["client_secret"])))


  return tag, max_chunk_size, file_tups, passphrase, salt





def load_and_save_tokens(refresh_token_file, data_file, client_id,
                         client_secret, disable_authorization_prompt=False):
  """Attempts to load the refresh token from the specified file and use it to
  acquire an access token from the REST API. If that fails, attempts to prompt
  user to authorize the client and enter the authorization code."""

  def __send_request(data_str, refresh_token):

    headers = ["Content-length:%d" % len(data_str),
               "Content-type:application/x-www-form-urlencoded"]

    request_time = time()
    response = BytesIO()

    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, AUTH_URI)
    curl.setopt(pycurl.TIMEOUT, CONNECT_TIMEOUT)
    curl.setopt(pycurl.HTTPHEADER, headers)
    curl.setopt(pycurl.POST, 1)
    curl.setopt(pycurl.POSTFIELDS, data_str)
    curl.setopt(pycurl.WRITEFUNCTION, response.write)
    curl.perform()
    curl.close()

    response_dict = json.loads(response.getvalue().decode("utf-8"))

    try:
      access_token = response_dict["access_token"]
      access_expire_time = request_time + response_dict["expires_in"] - EXPIRE_THRESHOLD
    except KeyError:
      raise ValueError(response_dict["error_description"])

    try:
      refresh_token = response_dict["refresh_token"]
    except KeyError: pass

    return access_token, refresh_token, access_expire_time



  needs_token = False
  refresh_token = None
  try:
    with open(refresh_token_file, "r") as f_in:
      refresh_token = f_in.read().strip()
  except:
    needs_token = True


  if not needs_token:
    data_str = "&".join(["refresh_token=%s" % refresh_token,
                         "grant_type=refresh_token", "client_id=%s" % client_id,
                         "client_secret=%s" % client_secret])
    try:
      return __send_request(data_str, refresh_token)
    except ValueError:
      needs_token = True


  if needs_token:
    if disable_authorization_prompt:
      raise ValueError("Client %s not authorized for storage access." % client_id)

    access_url = (ACCESS_TOKEN_URL+ "?"
                + "&".join(["scope=https:%2F%2Fwww.googleapis.com%2Fauth%2Fdrive",
                            "response_type=code", "redirect_uri=urn:ietf:wg:oauth:2.0:oob",
                            "client_id=%s" % client_id]))

    sys.stdout.write("\n%s:\n" % data_file)
    sys.stdout.write("Visit the following URL and grant access to Drive:\n\n%s\n\n" % access_url)
    sys.stdout.write("Then enter the authorization code below.\n\n")

    while True:
      sys.stdout.write("Authorization code: ")
      sys.stdout.flush()
      try:
        auth_code = raw_input()
      except:
        auth_code = input()
      if auth_code:
        break

    data_str = "&".join(["redirect_uri=urn:ietf:wg:oauth:2.0:oob",
                         "grant_type=authorization_code", "client_id=%s" % client_id,
                         "client_secret=%s" % client_secret, "code=%s" % auth_code])

    sys.stdout.write("Authorizing new client................")
    sys.stdout.flush()

    access_token, refresh_token, access_expire_time = __send_request(data_str, refresh_token)

    with open(refresh_token_file, "w") as f_out:
      f_out.write(refresh_token)

    return access_token, refresh_token, access_expire_time





def refresh_access_token(refresh_token, client_id, client_secret):
  """Attempts to refresh the short-lived access token for API access."""

  data_str = "&".join(["refresh_token=%s" % refresh_token,
                       "grant_type=refresh_token", "client_id=%s" % client_id,
                       "client_secret=%s" % client_secret])
  
  headers = ["Content-length:%d" % len(data_str),
             "Content-type:application/x-www-form-urlencoded"]

  request_time = time()
  response = BytesIO()

  curl = pycurl.Curl()
  curl.setopt(pycurl.URL, AUTH_URI)
  curl.setopt(pycurl.TIMEOUT, CONNECT_TIMEOUT)
  curl.setopt(pycurl.HTTPHEADER, headers)
  curl.setopt(pycurl.POST, 1)
  curl.setopt(pycurl.POSTFIELDS, data_str)
  curl.setopt(pycurl.WRITEFUNCTION, response.write)
  curl.perform()
  curl.close()

  response_dict = json.loads(response.getvalue().decode("utf-8"))

  try:
    access_token = response_dict["access_token"]
    access_expire_time = request_time + response_dict["expires_in"] - EXPIRE_THRESHOLD
  except KeyError:
    raise ValueError(response_dict["error_description"])

  return access_token, access_expire_time









def lookup_filename_ids(filenames, access_token):
  """Requests the id for each of the files in `filenames` and returns a
  dictionary mapping names to ids discovered with the specified token."""

  query = " or ".join(["name = '%s'" % f for f in filenames])
  
  name_id_map = {}
  next_page_token = None

  while True:
    request_uri = (FILES_URI + "?corpora=user&spaces=drive&q="
                   + url_escape(query, safe="") + "&prettyPrint=false")

    if next_page_token:
      request_uri += "&pageToken=%s" % next_page_token

    response = BytesIO()

    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, request_uri)
    curl.setopt(pycurl.TIMEOUT, CONNECT_TIMEOUT)
    curl.setopt(pycurl.HTTPHEADER, ["Authorization:Bearer %s" % access_token])
    curl.setopt(pycurl.WRITEFUNCTION, response.write)
    curl.perform()
    curl.close()

    response_dict = json.loads(response.getvalue().decode("utf-8"))

    for obj in response_dict["files"]:
      name_id_map[obj["name"]] = obj["id"]
    
    if "nextPageToken" in response_dict:
      next_page_token = response_dict["nextPageToken"]
    else:
      break

  return name_id_map



def lookup_revision_id(file_id, revision_index, access_token):
  """Looks up the revision id of the revision at the specified index, starting
  backwards from head. If no revision exists that old, an error is raised."""

  if revision_index < 0:
    raise ValueError("Negative revision index is invalid.")

  revision_ids = []
  next_page_token = None

  while True:

    request_uri = FILES_URI + "/%s" % file_id + "/revisions?prettyPrint=false"

    if next_page_token:
      request_uri += "&pageToken=%s" % next_page_token

    response = BytesIO()

    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, request_uri)
    curl.setopt(pycurl.TIMEOUT, CONNECT_TIMEOUT)
    curl.setopt(pycurl.HTTPHEADER, ["Authorization:Bearer %s" % access_token])
    curl.setopt(pycurl.WRITEFUNCTION, response.write)
    curl.perform()
    curl.close()

    response_dict = json.loads(response.getvalue().decode("utf-8"))

    for obj in response_dict["revisions"]:
      revision_ids.append(obj["id"])

    if "nextPageToken" in response_dict:
      next_page_token = response_dict["nextPageToken"]
    else:
      break


  if revision_index >= len(revision_ids):
    raise ValueError("No revision old enough.")

  return revision_ids[len(revision_ids)-1-revision_index]






def download_file_bytes(file_id, access_token, revision_id=None):
  """Downloads the contents of the file with the specified id and optionally the
  specified revision id."""

  request_uri = FILES_URI + "/%s" % file_id

  if revision_id:
    request_uri += "/revisions/%s" % revision_id

  request_uri += "?alt=media"


  response = BytesIO()

  curl = pycurl.Curl()
  curl.setopt(pycurl.URL, request_uri)
  curl.setopt(pycurl.TIMEOUT, CONNECT_TIMEOUT)
  curl.setopt(pycurl.HTTPHEADER, ["Authorization:Bearer %s" % access_token])
  curl.setopt(pycurl.WRITEFUNCTION, response.write)
  curl.perform()
  curl.close()

  return response.getvalue()






def upload_file_bytes(name, mime_type, content_bytes, access_token,
                      parent_folder_id=None, existing_file_id=None):
  """Uploads the specified content bytes. If `existing_file_id` is specified, the
  file contents are updated instead of creating a new file. Returns the id of the
  uploaded file and the head revision id if it exists. If an existing id is
  specified, parent id is ignored."""

  computed_md5sum = hashlib.md5(content_bytes).hexdigest()

  request_uri = UPLOAD_URI

  if existing_file_id:
    request_uri += "/%s" % existing_file_id

  request_uri += "?uploadType=multipart&prettyPrint=false&fields=id,md5Checksum,headRevisionId"


  json_dict = {"name": name, "mimeType": mime_type,
               "parents": [parent_folder_id] if parent_folder_id and not existing_file_id else []}

  data_str = b"\r\n".join([b"--***_sep_***",
                           b"Content-Type:application/json;charset=UTF-8", b"",
                           json.dumps(json_dict).encode("utf-8"), b"--***_sep_***",
                           b"Content-Type:%s" % mime_type.encode("ascii"), b"",
                           content_bytes, b"--***_sep_***--"])


  headers = ["Authorization:Bearer %s" % access_token,
             "Content-Type:multipart/related;boundary=***_sep_***",
             "Content-length:%d" % len(data_str)]


  successful = False

  for cur_retry in range(MAX_UPLOAD_RETRIES):
    if successful:
      break

    response = BytesIO()

    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, request_uri)
    curl.setopt(pycurl.TIMEOUT, CONNECT_TIMEOUT)
    curl.setopt(pycurl.HTTPHEADER, headers)
    if existing_file_id:
      curl.setopt(pycurl.CUSTOMREQUEST, "PATCH")
    else:
      curl.setopt(pycurl.POST, 1)
    curl.setopt(pycurl.POSTFIELDS, data_str)
    curl.setopt(pycurl.WRITEFUNCTION, response.write)
    curl.perform()
    curl.close()


    response_dict = json.loads(response.getvalue().decode("utf-8"))

    file_id = response_dict["id"]

    try:
      md5sum = response_dict["md5Checksum"]
      head_revision_id = response_dict["headRevisionId"]
      successful = md5sum.lower() == computed_md5sum
    except KeyError:
      md5sum = None
      head_revision_id = None
      successful = True


  if not successful:
    raise RuntimeError("Failed to upload file %s." % name)

  return file_id, head_revision_id






def create_folder(name, access_token):
  """Creates a new folder and returns its file id."""

  file_id, _ = upload_file_bytes(name, "application/vnd.google-apps.folder",
                                 b"", access_token)

  return file_id







def connect_clients(manifest_file, disable_authorization_prompt=False):
  """Reads the manifest file and connects each client to the storage server,
  returning per-connection tokens and filenames."""

  # Get all parameters out of the manifest JSON file.
  sys.stdout.write("Reading manifest......................")
  sys.stdout.flush()
  try:
    tag, max_chunk_size, file_tups, passphrase, salt = read_manifest_file(manifest_file)
  except Exception as e:
    sys.stdout.write("FAILED\n\n")
    sys.stderr.write(traceback.format_exc() + "\n")
    sys.exit(1)
  sys.stdout.write("OK\n")


  # Get the salted secret key used for AES256 encryption.
  prf = lambda secret, salt : hmac.new(secret, salt, hashlib.sha512).digest()
  secret_key = PBKDF2(passphrase.encode("utf-8"), salt.encode("utf-8"),
                      dkLen=32, count=100000, prf=prf)


  # Connect to each client listed in the manifest and cache connection info.
  client_access_tokens = {}
  client_refresh_tokens = {}
  client_meta_files = {}
  client_data_files = {}

  folder_params = [tag, binascii.hexlify(secret_key).decode("ascii"), max_chunk_size]
  folder_name = hashlib.sha256(json.dumps(folder_params).encode("utf-8")).hexdigest()

  for abs_data_file, orig_data_file, client_id, client_secret in file_tups:


    # Cache meta info filenames and data filenames for each client connection.
    meta_params = folder_params + [orig_data_file]
    meta_hash = hashlib.sha256(json.dumps(meta_params).encode("utf-8")).hexdigest()
    meta_file = "%s.bin" % meta_hash

    try:
      client_meta_files[client_id].append(meta_file)
      client_data_files[client_id].append(abs_data_file)
    except KeyError:
      client_meta_files[client_id] = [meta_file]
      client_data_files[client_id] = [abs_data_file]
    
    # Cache token information for each client connection.
    if client_id not in client_access_tokens:
      token_params = [client_id, client_secret]
      token_hash = hashlib.new("ripemd160", json.dumps(token_params).encode("utf-8")).hexdigest()
      token_file = os.path.join(os.path.dirname(manifest_file), "%s.token" % token_hash)

      sys.stdout.write("Connecting to storage.................")
      sys.stdout.flush()
      try:
        access_token, refresh_token, access_expire_time = load_and_save_tokens(token_file,
                                                                               abs_data_file,
                                                                               client_id,
                                                                               client_secret,
                                                                               disable_authorization_prompt)
        client_access_tokens[client_id] = (access_token, access_expire_time)
        client_refresh_tokens[client_id] = (refresh_token, client_id, client_secret)

      except Exception as e:
        sys.stdout.write("FAILED\n\n")
        sys.stderr.write(traceback.format_exc() + "\n")
        sys.exit(1)
      sys.stdout.write("OK\n")


  return (client_access_tokens, client_refresh_tokens, client_meta_files,
          client_data_files, folder_name, secret_key, max_chunk_size)





def get_file_ids_and_metadata(client_access_tokens, client_refresh_tokens,
                              client_meta_files, client_data_files, folder_name,
                              secret_key, revision_index):
  """Looks up file ids of metadata files for the specified revision, then
  downloads the meta file contents for each data file. Any data files that
  cannot be found on the server return empty metadata and meta ids of `None`."""

  file_meta_names = {}
  file_meta_ids = {}
  file_meta_revision_ids = {}
  file_client_ids = {}
  file_meta_data = {}
  client_folder_ids = {}

  sys.stdout.write("Getting file metadata.................")
  sys.stdout.flush()
  try:

    # Get file ids for all meta files on the storage drive and map data file
    # names to meta file names, ids, and clients.
    for client_id in client_meta_files:
      storage_files = [folder_name] + [f for f in client_meta_files[client_id]]
      access_token, access_expire_time = client_access_tokens[client_id]
      if time() >= access_expire_time:
        client_access_tokens[client_id] = refresh_access_token(*(client_refresh_tokens[client_id]))
        access_token, _ = client_access_tokens[client_id]

      name_id_map = lookup_filename_ids(storage_files, access_token)
      try:
        client_folder_ids[client_id] = name_id_map[folder_name]
      except KeyError:
        client_folder_ids[client_id] = None

      for meta_file, data_file in zip(client_meta_files[client_id],
                                      client_data_files[client_id]):
        file_meta_names[data_file] = meta_file
        file_client_ids[data_file] = client_id
        try:
          file_meta_ids[data_file] = name_id_map[meta_file]

          if revision_index != 0:
            file_meta_revision_ids[data_file] = lookup_revision_id(file_meta_ids[data_file],
                                                                   revision_index,
                                                                   access_token)
          else:
            file_meta_revision_ids[data_file] = None

        except KeyError:
          file_meta_ids[data_file] = None


    # Download the meta file content and map data file names to meta data.
    for data_file in file_meta_names:

      meta_id = file_meta_ids[data_file]
      
      if meta_id:
        client_id = file_client_ids[data_file]
        access_token, access_expire_time = client_access_tokens[client_id]
        if time() >= access_expire_time:
          client_access_tokens[client_id] = refresh_access_token(*(client_refresh_tokens[client_id]))
          access_token, _ = client_access_tokens[client_id]

        meta_content = download_file_bytes(meta_id, access_token,
                                           file_meta_revision_ids[data_file])
        meta_content = AES.new(secret_key, AES.MODE_CFB,
                               meta_content[:16]).decrypt(meta_content[16:])
        meta_content = zlib.decompress(meta_content)
        file_meta_data[data_file] = json.loads(meta_content.decode("utf-8"))

      else:
        file_meta_data[data_file] = {}


  except Exception as e:
    sys.stdout.write("FAILED\n\n")
    sys.stderr.write(traceback.format_exc() + "\n")
    sys.exit(1)
  sys.stdout.write("OK\n")


  return (file_meta_names, file_meta_ids, file_meta_data,
          file_client_ids, client_folder_ids)





def meta_data_to_shared(file_meta_data, mp_mgr):
  """Constructs a shared dictionary of nested shared meta data that can be
  manipulated by child processes."""

  shared_file_meta_data = mp_mgr.dict()
  for data_file in file_meta_data:
    d = mp_mgr.dict()
    d["size"] = file_meta_data[data_file]["size"]
    d["chunks"] = mp_mgr.list(file_meta_data[data_file]["chunks"])
    shared_file_meta_data[data_file] = d

  return shared_file_meta_data




def meta_data_from_shared(shared_file_meta_data):
  """Constructs a regular Python dictionary from nested shared meta data."""

  file_meta_data = {}
  for data_file in shared_file_meta_data.keys():
    d = {}
    d["size"] = shared_file_meta_data[data_file]["size"]
    d["chunks"] = list(shared_file_meta_data[data_file]["chunks"])
    file_meta_data[data_file] = d

  return file_meta_data




class UploadWorkerProcess(multiprocessing.Process):
  """Implements a multiprocessing Process object that asynchronously
  uploads file chunks."""

  def __init__(self, access_lock, transfer_lock, shared_ns,
               shared_client_access_tokens, shared_client_refresh_tokens,
               shared_client_folder_ids, shared_file_client_ids,
               shared_file_meta_names, shared_file_meta_data, shared_chunk_schedule):
    multiprocessing.Process.__init__(self)
    self._access_lock = access_lock
    self._transfer_lock = transfer_lock
    self._shared_ns = shared_ns
    self._shared_client_access_tokens = shared_client_access_tokens
    self._shared_client_refresh_tokens = shared_client_refresh_tokens
    self._shared_client_folder_ids = shared_client_folder_ids
    self._shared_file_client_ids = shared_file_client_ids
    self._shared_file_meta_names = shared_file_meta_names
    self._shared_file_meta_data = shared_file_meta_data
    self._shared_chunk_schedule = shared_chunk_schedule


  def run(self):
    """Enters the main loop for the process."""

    rng = Random.new()

    while True:
      try:
        data_file, chunk_ind = self._shared_chunk_schedule.get()
      except queue.Empty:
        break

      chunk_meta = self._shared_file_meta_data[data_file]["chunks"][chunk_ind]


      # Read the current chunk and compute its hash.
      with open(data_file, "rb") as f_in:
        f_in.seek(chunk_ind * self._shared_ns.max_chunk_size)
        data_content = f_in.read(self._shared_ns.max_chunk_size)
      data_length = len(data_content)
      data_hash = hashlib.sha512(data_content).hexdigest()


      # If hash doesn't match metadata, compress, encrypt, and upload chunk.
      if data_hash != chunk_meta["hash"]:
        chunk_meta["hash"] = data_hash

        data_content = zlib.compress(data_content, COMPRESSION_LEVEL)
        iv = rng.read(16)
        data_content = iv + AES.new(self._shared_ns.secret_key,
                                     AES.MODE_CFB, iv).encrypt(data_content)

        client_id = self._shared_file_client_ids[data_file]
        parent_id = self._shared_client_folder_ids[client_id]

        with self._access_lock:
          access_token, access_expire_time = self._shared_client_access_tokens[client_id]
          if time() >= access_expire_time:
            access_token, access_expire_time = refresh_access_token(*(self._shared_client_refresh_tokens[client_id]))
            self._shared_client_access_tokens[client_id] = (access_token, access_expire_time)


        name_params = [self._shared_file_meta_names[data_file], chunk_ind]
        name_hash = hashlib.sha256(json.dumps(name_params).encode("utf-8")).hexdigest()
        content_name = "%s.bin" % name_hash

        file_id, revision_id = upload_file_bytes(content_name, "application/octet-stream",
                                                 data_content, access_token,
                                                 parent_folder_id=parent_id,
                                                 existing_file_id=chunk_meta["file_id"])
        chunk_meta["file_id"] = file_id
        chunk_meta["rev_id"] = revision_id
        self._shared_file_meta_data[data_file]["chunks"][chunk_ind] = chunk_meta


      with self._transfer_lock:
        self._shared_ns.uploaded_so_far += data_length








def upload(manifest_file, disable_authorization_prompt=False, num_workers=4):
  """Connects to remote storage and launches worker threads to upload
  compressed, encrypted data."""

  tup = connect_clients(manifest_file, disable_authorization_prompt)
  client_access_tokens = tup[0]
  client_refresh_tokens = tup[1]
  client_meta_files = tup[2]
  client_data_files = tup[3]
  folder_name = tup[4]
  secret_key = tup[5]
  max_chunk_size = tup[6]

  tup = get_file_ids_and_metadata(client_access_tokens, client_refresh_tokens,
                                  client_meta_files, client_data_files, folder_name,
                                  secret_key, 0)
  file_meta_names = tup[0]
  file_meta_ids = tup[1]
  file_meta_data = tup[2]
  file_client_ids = tup[3]
  client_folder_ids = tup[4]
  


  # Determine number of chunks in each file, initialize non-existing meta data
  # for each chunk, and choose a random upload order.
  chunk_schedule = []
  total_upload_size = 0
  for data_file in file_meta_names:
    cur_size = os.path.getsize(data_file)
    total_upload_size += cur_size
    num_chunks = int(math.ceil(cur_size / float(max_chunk_size)))
    chunk_schedule.extend([(data_file, i) for i in range(num_chunks)])

    file_meta_data[data_file]["size"] = cur_size

    if "chunks" not in file_meta_data[data_file]:
      file_meta_data[data_file]["chunks"] = []

    while len(file_meta_data[data_file]["chunks"]) < num_chunks:
      file_meta_data[data_file]["chunks"].append({"hash": None, "file_id": None, "rev_id": None})
    file_meta_data[data_file]["chunks"] = file_meta_data[data_file]["chunks"][:num_chunks]

  shuffle(chunk_schedule)



  # Make sure folders exist for uploaded data on each client storage.
  for client_id in client_folder_ids:
    if not client_folder_ids[client_id]:
      access_token, access_expire_time = client_access_tokens[client_id]
      if time() >= access_expire_time:
        client_access_tokens[client_id] = refresh_access_token(*(client_refresh_tokens[client_id]))
        access_token, _ = client_access_tokens[client_id]
      client_folder_ids[client_id] = create_folder(folder_name, access_token)



  # Launch worker processes to perform the content upload and update progress.
  mp_mgr = multiprocessing.Manager()

  access_lock = mp_mgr.Lock()
  transfer_lock = mp_mgr.Lock()

  shared_ns = mp_mgr.Namespace()
  shared_ns.secret_key = secret_key
  shared_ns.max_chunk_size = max_chunk_size
  shared_ns.uploaded_so_far = 0

  shared_client_access_tokens = mp_mgr.dict(client_access_tokens)
  shared_client_refresh_tokens = mp_mgr.dict(client_refresh_tokens)
  shared_client_folder_ids = mp_mgr.dict(client_folder_ids)
  shared_file_client_ids = mp_mgr.dict(file_client_ids)
  shared_file_meta_names = mp_mgr.dict(file_meta_names)
  shared_file_meta_data = meta_data_to_shared(file_meta_data, mp_mgr)

  shared_chunk_schedule = mp_mgr.Queue()
  for tup in chunk_schedule:
    shared_chunk_schedule.put_nowait(tup)


  worker_processes = []
  for i in range(num_workers):
    proc = UploadWorkerProcess(access_lock, transfer_lock, shared_ns,
                               shared_client_access_tokens,
                               shared_client_refresh_tokens,
                               shared_client_folder_ids,
                               shared_file_client_ids, shared_file_meta_names,
                               shared_file_meta_data, shared_chunk_schedule)
    worker_processes.append(proc)
  

  for proc in worker_processes:
    proc.start()


  try:
    while True:
      with transfer_lock:
        uploaded_bytes = shared_ns.uploaded_so_far

      if uploaded_bytes >= total_upload_size:
        break

      progress = int(round((float(uploaded_bytes) / total_upload_size) * 100.))

      sys.stdout.write("Uploading file contents...............")
      sys.stdout.write("%d%%\r" % progress)
      sys.stdout.flush()
      sleep(PROGRESS_SLEEP_TIME)

  except Exception as e:
    sys.stdout.write("Uploading file contents...............FAILED\n")
    sys.stderr.write(traceback.format_exc() + "\n")
    sys.exit(1)
  sys.stdout.write("Uploading file contents...............OK  \n")


  for proc in worker_processes:
    proc.terminate()
    proc.join()



  # Get updated meta data and access tokens, then upload meta data to storage.
  client_access_tokens = dict(shared_client_access_tokens)
  file_meta_data = meta_data_from_shared(shared_file_meta_data)

  rng = Random.new()

  sys.stdout.write("Uploading meta data...................")
  sys.stdout.flush()

  try:
    for data_file in file_meta_data:
      client_id = file_client_ids[data_file]
      access_token, access_expire_time = client_access_tokens[client_id]
      if time() >= access_expire_time:
        client_access_tokens[client_id] = refresh_access_token(*(client_refresh_tokens[client_id]))
        access_token, _ = client_access_tokens[client_id]
      parent_id = client_folder_ids[client_id]

      meta_name = file_meta_names[data_file]
      meta_id = file_meta_ids[data_file]
      meta_content = json.dumps(file_meta_data[data_file]).encode("utf-8")
      meta_content = zlib.compress(meta_content, COMPRESSION_LEVEL)
      iv = rng.read(16)
      meta_content = iv + AES.new(secret_key, AES.MODE_CFB, iv).encrypt(meta_content)

      upload_file_bytes(meta_name, "application/octet-stream", meta_content,
                        access_token, parent_folder_id=parent_id,
                        existing_file_id=meta_id)

  except Exception as e:
    sys.stdout.write("FAILED\n")
    sys.stderr.write(traceback.format_exc() + "\n")
    sys.exit(1)
  sys.stdout.write("OK\n")











class DownloadWorkerProcess(multiprocessing.Process):
  """Implements a multiprocessing Process object that asynchronously
  downloads file chunks."""

  def __init__(self, access_lock, transfer_lock, shared_ns,
               shared_client_access_tokens, shared_client_refresh_tokens,
               shared_file_client_ids, shared_file_meta_data, shared_chunk_schedule):
    multiprocessing.Process.__init__(self)
    self._access_lock = access_lock
    self._transfer_lock = transfer_lock
    self._shared_ns = shared_ns
    self._shared_client_access_tokens = shared_client_access_tokens
    self._shared_client_refresh_tokens = shared_client_refresh_tokens
    self._shared_file_client_ids = shared_file_client_ids
    self._shared_file_meta_data = shared_file_meta_data
    self._shared_chunk_schedule = shared_chunk_schedule


  def run(self):
    """Enters the main loop for the process."""

    while True:
      try:
        data_file, chunk_ind = self._shared_chunk_schedule.get()
      except queue.Empty:
        break

      chunk_meta = self._shared_file_meta_data[data_file]["chunks"][chunk_ind]

      # Read the current chunk and compute its hash.
      with open(data_file, "r+b") as f_in_out:
        f_in_out.seek(chunk_ind * self._shared_ns.max_chunk_size)
        data_content = f_in_out.read(self._shared_ns.max_chunk_size)
        data_length = len(data_content)
        data_hash = hashlib.sha512(data_content).hexdigest()


        # If hash doesn't match metadata, download, decrypt, and decompress chunk.
        if data_hash != chunk_meta["hash"]:

          with self._access_lock:
            client_id = self._shared_file_client_ids[data_file]
            access_token, access_expire_time = self._shared_client_access_tokens[client_id]
            if time() >= access_expire_time:
              access_token, access_expire_time = refresh_access_token(*(client_refresh_tokens[client_id]))
              self._shared_client_access_tokens[client_id] = (access_token, access_expire_time)

          data_content = download_file_bytes(chunk_meta["file_id"], access_token,
                                             revision_id=chunk_meta["rev_id"])
          data_content = AES.new(self._shared_ns.secret_key, AES.MODE_CFB,
                                 data_content[:16]).decrypt(data_content[16:])
          data_content = zlib.decompress(data_content)

          f_in_out.seek(chunk_ind * self._shared_ns.max_chunk_size)
          f_in_out.write(data_content)


      with self._transfer_lock:
        self._shared_ns.downloaded_so_far += data_length






def download(manifest_file, revision, force_overwrite,
             disable_authorization_prompt=False, num_workers=4):
  """Creates local copies of data on the remote storage drive."""
  

  tup = connect_clients(manifest_file, disable_authorization_prompt)
  client_access_tokens = tup[0]
  client_refresh_tokens = tup[1]
  client_meta_files = tup[2]
  client_data_files = tup[3]
  folder_name = tup[4]
  secret_key = tup[5]
  max_chunk_size = tup[6]

  tup = get_file_ids_and_metadata(client_access_tokens, client_refresh_tokens,
                                  client_meta_files, client_data_files, folder_name,
                                  secret_key, revision)
  file_meta_names = tup[0]
  file_meta_ids = tup[1]
  file_meta_data = tup[2]
  file_client_ids = tup[3]
  client_folder_ids = tup[4]



  # Make sure files actually exist on storage by verifying that meta data
  # successfully downloaded.
  for data_file in file_meta_data:
    if "chunks" not in file_meta_data[data_file] or "size" not in file_meta_data[data_file]:
      raise RuntimeError("File %s not found on storage drive." % data_file)


  # Make sure files of the right size exist to place downloaded content into.
  if not force_overwrite:
    for data_file in file_meta_data:
      if os.path.exists(data_file):
        raise RuntimeError("File %s already exists. Use -f to overwrite." % data_file)

  for data_file in file_meta_data:
    target_size = file_meta_data[data_file]["size"]

    try:
      f_out = open(data_file, "r+b")
    except:
      f_out = open(data_file, "wb")

    try:
      f_out.seek(0, os.SEEK_END)
      cur_size = f_out.tell()
      if cur_size > target_size:
        f_out.truncate(target_size)
      else:
        f_out.seek(target_size-1, os.SEEK_SET)
        f_out.write(b"\x00")

    finally:
      f_out.close()




  # Get number of chunks in each file and choose a random download order.
  chunk_schedule = []
  total_download_size = 0
  for data_file in file_meta_names:
    total_download_size += file_meta_data[data_file]["size"]
    num_chunks = len(file_meta_data[data_file]["chunks"])
    chunk_schedule.extend([(data_file, i) for i in range(num_chunks)])
  shuffle(chunk_schedule)



  # Launch worker processes to perform the content upload and update progress.
  mp_mgr = multiprocessing.Manager()

  access_lock = mp_mgr.Lock()
  transfer_lock = mp_mgr.Lock()

  shared_ns = mp_mgr.Namespace()
  shared_ns.secret_key = secret_key
  shared_ns.max_chunk_size = max_chunk_size
  shared_ns.downloaded_so_far = 0

  shared_client_access_tokens = mp_mgr.dict(client_access_tokens)
  shared_client_refresh_tokens = mp_mgr.dict(client_refresh_tokens)
  shared_file_client_ids = mp_mgr.dict(file_client_ids)
  shared_file_meta_data = mp_mgr.dict(file_meta_data)

  shared_chunk_schedule = mp_mgr.Queue()
  for tup in chunk_schedule:
    shared_chunk_schedule.put_nowait(tup)


  worker_processes = []
  for i in range(num_workers):
    proc = DownloadWorkerProcess(access_lock, transfer_lock, shared_ns,
                                 shared_client_access_tokens,
                                 shared_client_refresh_tokens,
                                 shared_file_client_ids, shared_file_meta_data,
                                 shared_chunk_schedule)
    worker_processes.append(proc)
  

  for proc in worker_processes:
    proc.start()


  try:
    while True:
      with transfer_lock:
        downloaded_bytes = shared_ns.downloaded_so_far

      if downloaded_bytes >= total_download_size:
        break

      progress = int(round((float(downloaded_bytes) / total_download_size) * 100.))

      sys.stdout.write("Downloading file contents.............")
      sys.stdout.write("%d%%\r" % progress)
      sys.stdout.flush()
      sleep(PROGRESS_SLEEP_TIME)

  except Exception as e:
    sys.stdout.write("Downloading file contents.............FAILED\n")
    sys.stderr.write(traceback.format_exc() + "\n")
    sys.exit(1)
  sys.stdout.write("Downloading file contents.............OK  \n")


  for proc in worker_processes:
    proc.terminate()
    proc.join()







if __name__ == "__main__":

  action, args = parse_args()

  if action == "up":
    upload(*args)
  else:
    download(*args)
  

  



