'''
In real operation, you should delete the follwing lines.
- line 169
- lines from 128 to 131
'''

import csv
import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file"]


# Reference: https://developers.google.com/drive/api/reference/rest/v3/drives/list?hl=ja
def getAllSharedDrives(service, pageToken=None, drives=[]):
  results = service.drives().list(
    pageToken = pageToken,
    pageSize = 100,
    useDomainAdminAccess = True,
    fields="nextPageToken, drives(id, name)"
  ).execute()
  drives = drives + results.get("drives", [])
  # print("Number of drives: %d" % len(drives))

  if not 'nextPageToken' in results:
    # print(drives[0])
    return drives
  else:
    return getAllSharedDrives(service, results['nextPageToken'], drives)


# Reference: https://developers.google.com/drive/api/reference/rest/v3/files/list?hl=ja
def getAllItemsInDrive(service, driveId, pageToken=None, items=[]):
  results = service.files().list(
    corpora="drive",
    driveId=driveId,
    includeItemsFromAllDrives=True,
    supportsAllDrives=True,
    pageToken = pageToken,
    pageSize=500,
    fields="nextPageToken, files(parents, id, name, mimeType)"
  ).execute()
  items = items + results.get("files", [])
  print("Number of items: %d" % len(items))

  if not 'nextPageToken' in results:
    return items
  else:
    return getAllItemsInDrive(service, driveId, results['nextPageToken'], items)


# Reference: https://developers.google.com/drive/api/reference/rest/v3/permissions/list?hl=ja
def getAllPermissionsInItem(service, folderId, pageToken=None, permissions=[]):
  results = service.permissions().list(
    pageToken = pageToken,
    pageSize=100,
    fileId=folderId,
    supportsAllDrives=True,
    fields="nextPageToken, permissions(id, displayName, emailAddress, type, role)"
  ).execute()
  permissions = permissions + results.get("permissions", [])
  # print("Number of permissions: %d" % len(permissions))

  if not 'nextPageToken' in results:
    # print(permissions[0])
    return permissions
  else:
    return getAllPermissionsInItem(service, folderId, results['nextPageToken'], permissions)


# If the file is shared a user not having "@your_domain" domain, it is determined an external shared item
def checkExtSharedFolders(service, folderId):
  isShared = False
  permissions = getAllPermissionsInItem(service, folderId)

  # print("Permissions:")
  for permission in permissions:
    email = permission['emailAddress']
    # displayName = permission['displayName']
    # pType = permission['type']
    # pRole = permission['role']
    # print(f"{displayName} / {email} ({pType}, {pRole})")
    if not "@your_domain" in email:
      isShared = True
      break
  return [isShared, email]


def main():
  """
  Shows basic usage of the Drive v3 API.
  Prints the names and ids of the first 10 files the user has access to.
  """
  creds = None
  # The file token.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first
  # time.
  if os.path.exists("token.json"):
    creds = Credentials.from_authorized_user_file("token.json", SCOPES)
  # If there are no (valid) credentials available, let the user log in.
  if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())
    else:
      flow = InstalledAppFlow.from_client_secrets_file(
          "credentials.json", SCOPES
      )
      creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open("token.json", "w") as token:
      token.write(creds.to_json())

  try:
    service = build("drive", "v3", credentials=creds)
    domain = "caddi.jp"

    drives = getAllSharedDrives(service)

    for drive in drives:
      driveId = drive['id']
      driveName = drive['name']
      # [Test]
      if driveId != "0AHWpboBfWVBLUk9PVA":    # cp-honbu
        continue
      # [/Test]
      print(f"Drive: {driveName} ({driveId})")
      items = getAllItemsInDrive(service, driveId)

      if not items:
        print("No files found.")
        return

      print("Files:")
      cnt, ind = 1, 0
      end = len(items)
      output = [
        ["driveName","folderId","parent","name","1stSharedUser"]
      ]
      while True:
        item = items[ind]
        if item['mimeType'] == 'application/vnd.google-apps.folder':
          folderId = item['id']
          isShared = checkExtSharedFolders(service, folderId)
          if not isShared[0]:
            print(f"Item {cnt}: {item['name']} is not an ext-shared folder.")
            items.remove(item)
          else:
            print(f"Item {cnt}: {item['name']} is an ext-shared folder!")
            output.append([driveName, folderId, item['parents'][0], item['name'], isShared[1]])
            ind += 1
        else:
          print(f"Item {cnt}: {item['name']} is not a folder.")
          items.remove(item)
        if cnt == end:
          break
        cnt += 1
      
      print("Number of ext-shared folders in %s: %d" % (driveName, len(items)))
      csvPath = "output/" + driveName + ".csv"
      with open(csvPath, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(output)
      break   # <-- Delete in real operation

  except HttpError as error:
    # TODO(developer) - Handle errors from drive API.
    print(f"An error occurred: {error}")


if __name__ == "__main__":
  main()
# [END drive_quickstart]
