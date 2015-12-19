# This is NOT the official repo for osslsigncode  
This project was copied from osslsigncode 1.7.1 to apply some patches for compiling with cygwin and being able to add unauthenticated blobs.  The official source for the project is at: http://sourceforge.net/projects/osslsigncode/

## Features added
Adds the argument "-addUnauthenticatedBlob" to add a 1024 byte unauthenticated blob of data to the signature in the same area as the timestamp.  This can be used while signing, while timestamping (new `add` command added to allow just time-stamping, after a file has been code signed, or by itself.

Examples:
```
# Example 1. Sign and add blob to unsigned file
osslsigncode sign -addUnauthenticatedBlob -pkcs12 yourcert.pfx -pass your_password -n "Your Company" -i https://YourSite.com/ -in srepp.msi -out srepp_added.msi
```

```
# Example 2. Timestamp and add blob to signed file 
osslsigncode.exe add -addUnauthenticatedBlob -t http://timestamp.verisign.com/scripts/timstamp.dll -in your_signed_file.exe -out out.exe
```

```
# Example 3. Add blob to signed and time-stamped file 
osslsigncode.exe add -addUnauthenticatedBlob -in your_signed_file.exe -out out.exe
```

```
# Example 4. Sign, timestamp, and add blob
# Technically you can do this, but this would mean your signing certificate 
# is on a computer that is connected the Internet, 
# which means you are doing something wrong, 
# so I'm not going to show how to do that.

```

This technique (but not this project) is used by Dropbox, GoToMeeting, and Summit Route.  You can read more about this technique here:

- https://tech.dropbox.com/2014/08/tech-behind-dropboxs-new-user-experience-for-mobile/
- http://blogs.msdn.com/b/ieinternals/archive/2014/09/04/personalizing-installers-using-unauthenticated-data-inside-authenticode-signed-binaries.aspx


## WARNING
The capability this adds can allow you to do dumb things.  Be very careful with what you put in the unauthenticated blob, as an attacker could modify this.  Do NOT under any circumstances put a URL here that you will use to download an additional file.  If you do do that, you would need to check the newly downloaded file is code signed AND that it has been signed with your cert AND that it is the version you expect.  You should consider using asymmetrical encryption for the data you put in the blob, such that the executable contains the public key to decrypt the data.  Basically, be VERY careful.  


## Compiling under cygwin

- Ensure you install the development libraries for openssl, libgfs, and curl.
- Install pkg-config
- Run
```
export SHELLOPTS
set -o igncr
./configure
make
```

## Download

- Compiled binary for cygwin: https://summitroute.com/downloads/osslsigncode.exe
- Compiled binary plus all the required DLL's (self-extracting exe): https://summitroute.com/downloads/osslsigncode-cygwin_files.exe
