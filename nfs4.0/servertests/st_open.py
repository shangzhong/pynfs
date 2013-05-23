from nfs4_const import *
from environment import check, checklist, checkdict, get_invalid_utf8strings
from nfs4lib import get_bitnumattr_dict
import time
import os

def _informFileOpened(c, env):
    """Inform the master script that file is opened.
    """
    env.fifohelper("open y")

def _waitForNextStep(c, env):
    """Waits for  master script to signal go ahead.
    """
    env.fifohelper("wait")

def _waitForOtherClient(c, env):
    """Wait for server to reboot.

    Returns an estimate of how long grace period will last.
    """
    env.serverhelper("execute multiclient test")
    # Wait until the server is back up.
    # c.null() blocks until it gets a response,
    # which happens when the server comes back up.
    c.null()
    return 1


# Any test that uses create_confirm should depend on this test
def testOpen(t, env):
    """OPEN normal file with CREATE and GUARDED flags

    FLAGS: open openconfirm all
    DEPEND: INIT
    CODE: MKFILE
    """
    c = env.c1
    c.init_connection()
    c.create_confirm(t.code)

def testCreateUncheckedFile(t, env):
    """OPEN normal file with create and unchecked flags

    FLAGS: open all
    DEPEND: INIT
    CODE: OPEN2
    """
    c = env.c1
    c.init_connection()

    # Create the file
    orig_attrs = { FATTR4_MODE: 0644, FATTR4_SIZE: 32 }
    res = c.create_file(t.code, attrs=orig_attrs,  deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="Trying to create file %s" % t.code)
    fh, stateid = c.confirm(t.code, res)
    rcvd_attrs = c.do_getattrdict(fh, orig_attrs.keys())
    checkdict(orig_attrs, rcvd_attrs, get_bitnumattr_dict(),
              "Checking attrs on creation")
    # Create the file again...it should ignore attrs
    attrs = { FATTR4_MODE: 0600, FATTR4_SIZE: 16 }
    res = c.create_file(t.code, attrs=attrs,  deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="Trying to recreate file %s" % t.code)
    fh, stateid = c.confirm(t.code, res)
    rcvd_attrs = c.do_getattrdict(fh, orig_attrs.keys())
    checkdict(orig_attrs, rcvd_attrs, get_bitnumattr_dict(),
              "Attrs on recreate should be ignored")
    # Create the file again, should truncate size to 0 and ignore other attrs
    attrs = { FATTR4_MODE: 0600, FATTR4_SIZE: 0 }
    res = c.create_file(t.code, attrs=attrs,  deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="Trying to truncate file %s" % t.code)
    fh, stateid = c.confirm(t.code, res)
    rcvd_attrs = c.do_getattrdict(fh, orig_attrs.keys())
    expect = { FATTR4_MODE: 0644, FATTR4_SIZE: 0 }
    checkdict(expect, rcvd_attrs, get_bitnumattr_dict(),
              "Attrs on recreate should be ignored, except for size")
        
def testCreatGuardedFile(t, env):
    """OPEN normal file with create and guarded flags

    FLAGS: open all
    DEPEND: INIT
    CODE: OPEN3
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.code, mode=GUARDED4)
    check(res, msg="Trying to do guarded create of file %s" % t.code)
    c.confirm(t.code, res)
    # Create the file again, should return an error
    res = c.create_file(t.code, mode=GUARDED4)
    check(res, NFS4ERR_EXIST,
          "Trying to do guarded recreate of file %s" % t.code)

# FRED - CITI does not return an attr - warn about this?
def testCreatExclusiveFile(t, env):
    """OPEN normal file with create and exclusive flags

    FLAGS: open all
    DEPEND: INIT
    CODE: OPEN4
    """
    c = env.c1
    c.init_connection()
    # Create the file
    res = c.create_file(t.code, mode=EXCLUSIVE4, verifier='12345678', deny=OPEN4_SHARE_DENY_NONE)
    checklist(res, [NFS4_OK, NFS4ERR_NOTSUPP],
              "Trying to do exclusive create of file %s" % t.code)
    if res.status == NFS4ERR_NOTSUPP:
        c.fail_support("Exclusive OPEN not supported")
    fh, stateid = c.confirm(t.code, res)
    # Create the file again, should return an error
    res = c.create_file(t.code, mode=EXCLUSIVE4, verifier='87654321', deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_EXIST,
          "Trying to do exclusive recreate of file %s" % t.code)
    # Create with same verifier should return same object
    res = c.create_file(t.code, mode=EXCLUSIVE4, verifier='12345678', deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="Trying to do exclusive recreate of file %s" % t.code)
    newfh, stateid = c.confirm(t.code, res)
    if fh != newfh:
        c.fail("Filehandle changed on duplicate exclusive create")

def testOpenFile(t, env):
    """OPEN normal file with nocreate flag

    FLAGS: open openconfirm file all
    DEPEND: INIT LOOKFILE
    CODE: OPEN5
    """
    c = env.c1
    c.init_connection()
    c.open_confirm(t.code, env.opts.usefile)
                       
def testOpenVaporFile(t, env):
    """OPEN non-existant file with nocreate flag should return NFS4ERR_NOENT

    FLAGS: open all
    DEPEND: INIT MKDIR
    CODE: OPEN6
    """
    c = env.c1
    c.init_connection()
    res = c.create_obj(c.homedir + [t.code])
    check(res)
    res = c.open_file(t.code, c.homedir + [t.code, 'vapor'])
    check(res, NFS4ERR_NOENT,
          "Trying to open nonexistant file %s/vapor" % t.code)

    
def testDir(t, env):
    """OPEN with a directory should return NFS4ERR_ISDIR

    FLAGS: open dir all
    DEPEND: INIT LOOKDIR
    CODE: OPEN7d
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.usedir)
    check(res, NFS4ERR_ISDIR, "Trying to OPEN dir")
    
def testLink(t, env):
    """OPEN with a symlink should return NFS4ERR_SYMLINK

    FLAGS: open symlink all
    DEPEND: INIT LOOKLINK
    CODE: OPEN7a
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.uselink)
    check(res, NFS4ERR_SYMLINK, "Trying to OPEN symbolic link")
    
def testBlock(t, env):
    """OPEN with a block device should return NFS4ERR_INVAL

    FLAGS: open block all
    DEPEND: INIT LOOKBLK
    CODE: OPEN7b
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.useblock)
    check(res, NFS4ERR_SYMLINK, "Trying to OPEN block device")

def testChar(t, env):
    """OPEN with a character device should return NFS4ERR_INVAL

    FLAGS: open char all
    DEPEND: INIT LOOKCHAR
    CODE: OPEN7c
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.usechar)
    check(res, NFS4ERR_SYMLINK, "Trying to OPEN character device")

def testSocket(t, env):
    """OPEN with a socket should return NFS4ERR_INVAL

    FLAGS: open socket all
    DEPEND: INIT LOOKSOCK
    CODE: OPEN7s
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.usesocket)
    check(res, NFS4ERR_SYMLINK, "Trying to OPEN socket")

def testFifo(t, env):
    """OPEN with a fifo should return NFS4ERR_INVAL

    FLAGS: open fifo all
    DEPEND: INIT LOOKFIFO
    CODE: OPEN7f
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.usefifo)
    check(res, NFS4ERR_SYMLINK, "Trying to OPEN fifo")

def testNoFh(t, env):
    """OPEN should fail with NFS4ERR_NOFILEHANDLE if no (cfh)

    FLAGS: open emptyfh all
    DEPEND: INIT
    CODE: OPEN8
    """
    c = env.c1
    c.init_connection()
    ops = [c.open(t.code, t.code)]
    res = c.compound(ops)
    c.advance_seqid(t.code, res)
    check(res, NFS4ERR_NOFILEHANDLE, "OPEN with no <cfh>")
    
def testZeroLenName(t, env):
    """OPEN with zero length name should return NFS4ERR_INVAL

    FLAGS: open all
    DEPEND: INIT
    CODE: OPEN10
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.code, c.homedir + [''])
    check(res, NFS4ERR_INVAL, "OPEN with zero-length name")

def testLongName(t, env):
    """OPEN should fail with NFS4ERR_NAMETOOLONG with long filenames

    FLAGS: open longname all
    DEPEND: INIT
    CODE: OPEN11
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.code,  c.homedir + [env.longname])
    check(res, NFS4ERR_NAMETOOLONG, "OPEN with very long name")
    
def testNotDir(t, env):
    """OPEN with cfh not a directory should return NFS4ERR_NOTDIR

    FLAGS: open file all
    DEPEND: INIT LOOKFILE
    CODE: OPEN12
    """
    c = env.c1
    c.init_connection()
    res = c.open_file(t.code, env.opts.usefile + ['foo'])
    check(res, NFS4ERR_NOTDIR, "Trying to OPEN with cfh a file")
       
def testInvalidUtf8(t, env):
    """OPEN with bad UTF-8 name strings should return NFS4ERR_INVAL

    FLAGS: open utf8
    DEPEND: MKDIR
    CODE: OPEN13
    """
    c = env.c1
    c.init_connection()
    res = c.create_obj(c.homedir + [t.code])
    check(res)
    for name in get_invalid_utf8strings():
        res = c.create_file(t.code, c.homedir + [t.code, name])
        check(res, NFS4ERR_INVAL, "Trying to open file with invalid utf8 "
                                  "name %s/%s" % (t.code, repr(name)[1:-1]))

def testInvalidAttrmask(t, env):
    """OPEN should fail with NFS4ERR_INVAL on invalid attrmask

    Comments: We are using a read-only attribute on OPEN, which
    should return NFS4ERR_INVAL.

    FLAGS: open all
    DEPEND: INIT
    CODE: OPEN14
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.code, attrs={FATTR4_LINK_SUPPORT: TRUE})
    check(res, NFS4ERR_INVAL, "Trying to OPEN with read-only attribute")

def testUnsupportedAttributes(t, env):
    """OPEN should fail with NFS4ERR_ATTRNOTSUPP on unsupported attrs

    FLAGS: open all
    DEPEND: INIT LOOKFILE
    CODE: OPEN15
    """
    c = env.c1
    c.init_connection()
    supported = c.supportedAttrs(env.opts.usefile)
    count = 0
    for attr in env.attr_info:
        if attr.writable and not supported & attr.mask:
            count += 1
            res = c.create_file(t.code, attrs={attr.bitnum : attr.sample})
            check(res, NFS4ERR_ATTRNOTSUPP,
                  "Trying to OPEN with unsupported attribute")
    if count==0:
        t.pass_warn("There were no unsupported writable attributes, "
                    "nothing tested")

def testClaimPrev(t, env):
    """OPEN with CLAIM_PREVIOUS should return NFS4ERR_RECLAIM_BAD

    Note this assumes test is run after grace period has expired.
    (To actually ensure return of _NO_GRACE, see REBT3 test)
    
    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN16
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.open_file(t.code, fh, claim_type=CLAIM_PREVIOUS, deleg_type=OPEN_DELEGATE_NONE)
    checklist(res, [NFS4ERR_RECLAIM_BAD, NFS4ERR_NO_GRACE],
            "Trying to OPEN with CLAIM_PREVIOUS")

def testModeChange(t, env):
    """OPEN conflicting with mode bits

    FLAGS: open all mode000
    DEPEND: MODE MKFILE
    CODE: OPEN17
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code)
    res = c.close_file(t.code, fh, stateid)
    check(res)
    ops = c.use_obj(fh) + [c.setattr({FATTR4_MODE:0})]
    res = c.compound(ops)
    check(res, msg="Setting mode of file %s to 000" % t.code)
    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_BOTH,
                      deny=OPEN4_SHARE_DENY_NONE)
    if env.opts.uid == 0:
	    checklist(res, [NFS4_OK, NFS4ERR_ACCESS], "Opening file %s with mode=000" % t.code)
    else:
	    check(res, NFS4ERR_ACCESS, "Opening file %s with mode=000" % t.code)

def testShareConflict1(t, env):
    """OPEN conflicting with previous share
    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN18
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH)
    res = c.open_file('newowner', file, deny=OPEN4_SHARE_DENY_WRITE)
    check(res, NFS4ERR_SHARE_DENIED,
          "Trying to open a file with deny=WRITE "
          "that was already opened with access=WRITE")

def testFailedOpen(t, env):
    """MULTIPLE: failed open should not mess up other clients' filehandles

    FLAGS: open all
    DEPEND: MKFILE MODE MKDIR
    CODE: OPEN20
    """
    c1 = env.c1
    c1.init_connection()
    # Client 1: create a file and deny others access
    fh, stateid = c1.create_confirm(t.code)
    ops = c1.use_obj(fh) + [c1.setattr({FATTR4_MODE: 0700})]
    check(c1.compound(ops))
    # Client 2: try to open the file
    c2 = env.c2
    c2.init_connection()
    res = c2.open_file(t.code)
    check(res, NFS4ERR_ACCESS, "Opening file with mode 0700 as 'other'")
    # Client 1: try to use fh, stateid
    res1 = c1.lock_file(t.code, fh, stateid)
    check(res1, msg="Locking file after another client had a failed open")
    res = c1.write_file(fh, 'data', 0, stateid)
    check(res, msg="Writing with write lock")
    res = c1.unlock_file(1, fh, res1.lockid)
    check(res, msg="Unlocking file after write")
    res = c1.close_file(t.code, fh, stateid)
    check(res, msg="Closing file after lock/write/unlock sequence")

def testDenyRead1(t, env):
    """OPEN with access=read on a read-denied file

    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN21
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code, access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_READ)
    # Same owner, should fail despite already having read access
    # This is stated in both 14.2.16 and 8.9
    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_READ,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_SHARE_DENIED,
          "OPEN with access==read on a read-denied file")
    
def testDenyRead2(t, env):
    """OPEN with access=read on a read-denied file

    NFS4ERR_SHARE_DENIED return is specified in 14.2.16
    NFS4ERR_DENIED return is specified in  8.9

    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN22
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm('owner1', file,
                                   access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_READ)
    res = c.open_file('owner2', file, access=OPEN4_SHARE_ACCESS_READ,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_SHARE_DENIED,
          "OPEN with access==read on a read-denied file")
    
def testDenyRead3(t, env):
    """READ on a read-denied file

    NFS4ERR_LOCKED return is specified in 8.1.4:
        seems to apply to conflicts due to an OPEN(deny=x)
    NFS4ERR_ACCESS return is specified in 14.2.16:
        seems to apply to principle not having access to file
    NFS4ERR_OPENMODE return is specified in 8.1.4:
        (does not apply to special stateids) Why is this again?
        seems to apply to doing WRITE on OPEN(allow=read)

    FLAGS: open read all
    DEPEND: MKFILE
    CODE: OPEN23
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code,
                                   access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_READ)
    res = c.write_file(fh, 'data', 0, stateid)
    check(res)
    # Try to read file w/o opening
    res = c.read_file(fh)
    check(res, NFS4ERR_LOCKED, "Trying to READ a read-denied file")

def testDenyRead3a(t, env):
    """READ on a access_write file

    NFS4_OK is allowed per sect 8.1.4 of RFC, and many clients expect it
    
    FLAGS: open read all
    DEPEND: MKFILE
    CODE: OPEN23b
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code,
                                   access=OPEN4_SHARE_ACCESS_WRITE,
                                   deny=OPEN4_SHARE_DENY_NONE)
    res = c.write_file(fh, 'data', 0, stateid)
    check(res)
    # Try to read file 
    res2 = c.read_file(fh, stateid=stateid)
    check(res2, NFS4_OK, "Read an access_write file", [NFS4ERR_OPENMODE])

def testDenyRead4(t, env):
    """WRITE on a read-denied file

    FLAGS: open write all
    DEPEND: MKFILE
    CODE: OPEN24
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh1, stateid1 = c.create_confirm('owner1', file,
                                     access=OPEN4_SHARE_ACCESS_BOTH,
                                     deny=OPEN4_SHARE_DENY_READ)
    res = c.write_file(fh1, 'data', 0, stateid1)
    check(res)
    # Try to write file
    fh2, stateid2 = c.open_confirm('owner2', file,
                                     access=OPEN4_SHARE_ACCESS_WRITE,
                                     deny=OPEN4_SHARE_DENY_NONE)
    res2 = c.write_file(fh2, 'data', 0, stateid2)
    check(res2, msg="WRITE a read-denied file")

def testDenyWrite1(t, env):
    """OPEN with access=write on a write-denied file

    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN25
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code, access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_WRITE)
    # Same owner, should fail despite already having read access
    # This is stated in both 14.2.16 and 8.9
    res = c.open_file(t.code, access=OPEN4_SHARE_ACCESS_WRITE,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_SHARE_DENIED,
          "OPEN with access==write on a write-denied file")
    
def testDenyWrite2(t, env):
    """OPEN with access=write on a write-denied file

    NFS4ERR_SHARE_DENIED return is specified in 14.2.16
    NFS4ERR_DENIED return is specified in  8.9

    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN26
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm('owner1', file,
                                   access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_WRITE)
    res = c.open_file('owner2', file, access=OPEN4_SHARE_ACCESS_WRITE,
                      deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4ERR_SHARE_DENIED,
          "OPEN with access==write on a write-denied file")

def testDenyWrite3(t, env):
    """WRITE a write-denied file

    see OPEN23 comments

    FLAGS: open write all
    DEPEND: MKFILE
    CODE: OPEN27
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.code,
                                   access=OPEN4_SHARE_ACCESS_BOTH,
                                   deny=OPEN4_SHARE_DENY_WRITE)
    res = c.write_file(fh, 'data', 0, stateid)
    check(res)
    # Try to write using stateid=0
    res = c.write_file(fh, 'moredata')
    check(res, NFS4ERR_LOCKED, "Trying to WRITE a write-denied file")

def testDenyWrite4(t, env):
    """READ on a write-denied file

    FLAGS: open read all
    DEPEND: MKFILE
    CODE: OPEN28
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh1, stateid1 = c.create_confirm('owner1', file,
                                     access=OPEN4_SHARE_ACCESS_BOTH,
                                     deny=OPEN4_SHARE_DENY_WRITE)
    res = c.write_file(fh1, 'data', 0, stateid1)
    check(res)
    # Try to read file
    fh2, stateid2 = c.open_confirm('owner2', file,
                                     access=OPEN4_SHARE_ACCESS_READ,
                                     deny=OPEN4_SHARE_DENY_NONE)
    res2 = c.read_file(fh2, stateid=stateid2)
    check(res2, msg="READ a write-denied file")
    if res2.eof != TRUE or res2.data != 'data':
        t.fail("READ returned %s, expected 'data'" % repr(res2.data))


def testUpgrades(t, env):
    """OPEN read, write, and read-write, then close

    Inspired by a linux nfsd regression: the final close closes all the
    opens, and nfsd did that right, but some misaccounting somewhere
    leaked a file reference with the result that the filesystem would be
    unmountable after running this test.

    FLAGS: open all
    DEPEND: MKFILE
    CODE: OPEN29
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    owner = t.code
    c.create_confirm(owner, file, access=OPEN4_SHARE_ACCESS_READ,
                                     deny=OPEN4_SHARE_DENY_NONE)
    c.open_file(owner, file, access=OPEN4_SHARE_ACCESS_WRITE,
                                     deny=OPEN4_SHARE_DENY_NONE)
    res = c.open_file(owner, file, access=OPEN4_SHARE_ACCESS_BOTH,
                                     deny=OPEN4_SHARE_DENY_NONE)
    check(res)
    fh = res.resarray[-1].switch.switch.object
    stateid = res.resarray[-2].switch.switch.stateid
    c.close_file(owner, fh, stateid)

def testReplay(t, env):
    """Send the same OPEN twice

    FLAGS: open seqid all
    DEPEND: MKFILE
    CODE: OPEN30
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    owner = t.code
    fh, stateid = c.create_confirm(owner, file, deny=OPEN4_SHARE_DENY_NONE)
    res = c.close_file(owner, fh, stateid)
    seqid = c.get_seqid(owner)
    res = c.open_file(owner, file, deny=OPEN4_SHARE_DENY_BOTH)
    check(res)
    c.seqid[owner] -= 1
    res = c.open_file(owner, file, deny=OPEN4_SHARE_DENY_BOTH)
    check(res, msg="replayed open should succeed again")
    res = c.open_file(owner, file, deny=OPEN4_SHARE_DENY_BOTH)
    check(res, NFS4ERR_SHARE_DENIED, msg="non-replayed open should fail")

def testBadSeqid(t, env):
    """OPEN with a bad seqid

    FLAGS: open seqid all
    DEPEND: MKFILE
    CODE: OPEN31
    """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    owner = t.code
    fh, stateid = c.create_confirm(owner, file, deny=OPEN4_SHARE_DENY_NONE)
    c.seqid[owner] += 1
    res = c.open_file(owner, file, deny=OPEN4_SHARE_DENY_BOTH)
    check(res, NFS4ERR_BAD_SEQID)

# Current ACCESS=READ, DENY=NONE
def testShareUnit1(t, env):
    """OPEN conflicting with previous share
        FLAGS: all share
        DEPEND: MKFILE
        CODE: SHARE1
        """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)

    res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4_OK,
              "Trying to open a file with access=%s, deny=%s "
              "that was already opened with access=READ, deny=NONE" % ('READ', 'NONE'))
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="CLOSE a file")

def testShareUnit2(t, env):
    """OPEN conflicting with previous share
        FLAGS: all share
        DEPEND: MKFILE
        CODE: SHARE2
        """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)

    res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
    check(res, NFS4ERR_SHARE_DENIED,
              "Trying to open a file with access=%s, deny=%s "
              "that was already opened with access=READ, deny=NONE" % ('READ', 'READ'))                
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="CLOSE a file")

def testShareUnit3(t, env):
    """OPEN conflicting with previous share
        FLAGS: all share
        DEPEND: MKFILE
        CODE: SHARE3
        """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)

    res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
    check(res, NFS4_OK,
              "Trying to open a file with access=%s, deny=%s "
              "that was already opened with access=READ, deny=NONE" % ('READ', 'WRITE'))                
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="CLOSE a file")

def testShareUnit4(t, env):
    """OPEN conflicting with previous share
        FLAGS: all share
        DEPEND: MKFILE
        CODE: SHARE4
        """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    
    res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
    check(res, NFS4ERR_SHARE_DENIED,
          "Trying to open a file with access=%s, deny=%s "
          "that was already opened with access=READ, deny=NONE" % ('READ', 'BOTH'))             
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="CLOSE a file")

def testShareUnit5(t, env):
    """OPEN conflicting with previous share
        FLAGS: all share
        DEPEND: MKFILE
        CODE: SHARE5
        """
    c = env.c1
    c.init_connection()
    file = c.homedir + [t.code]
    fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
    
    res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
    check(res, NFS4_OK,
          "Trying to open a file with access=%s, deny=%s "
          "that was already opened with access=READ, deny=NONE" % ('WRITE', 'NONE'))             
    res = c.close_file(t.code, fh, stateid)
    check(res, msg="CLOSE a file")

def testShareUnit6(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE6
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('WRITE', 'READ'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit7(t, env):
  """OPEN conflicting with previous share
    FLAGS:share
    DEPEND: MKFILE
    CODE: SHARE7
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('WRITE', 'WRITE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit8(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE8
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('WRITE', 'BOTH'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit9(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE9
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('BOTH', 'NONE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit10(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE10
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('BOTH', 'READ'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit11(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE11
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('BOTH', 'WRITE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit12(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE12
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=NONE" % ('BOTH', 'BOTH'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=READ, DENY=READ
def testShareUnit13(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE13
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('READ', 'NONE'))                
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit14(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE14
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('READ', 'READ'))                
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit15(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE15
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('READ', 'WRITE'))                
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit16(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE16
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('READ', 'BOTH'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit17(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE17
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('WRITE', 'NONE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit18(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE18
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('WRITE', 'READ'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit19(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE19
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('WRITE', 'WRITE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit20(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE20
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('WRITE', 'BOTH'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit21(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE21
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('BOTH', 'NONE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit22(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE22
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('BOTH', 'READ'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit23(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE23
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('BOTH', 'WRITE'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit24(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE24
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=READ" % ('BOTH', 'BOTH'))             
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=READ, DENY=WRITE
def testShareUnit25(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE25
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit26(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE26
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit27(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE27
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit28(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE28
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit29(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE29
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit30(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE30
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit31(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE31
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit32(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE32
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit33(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE33
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit34(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE34
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit35(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE35
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit36(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE36
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=WRITE" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=READ, DENY=BOTH
def testShareUnit37(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE37
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit38(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE38
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit39(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE39
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit40(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE40
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit41(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE41
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit42(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE42
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit43(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE43
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit44(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE44
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit45(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE45
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit46(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE46
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit47(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE47
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit48(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE48
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=READ, deny=BOTH" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=WRITE, DENY=NONE
def testShareUnit49(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE49
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit50(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE50
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit51(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE51
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit52(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE52
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit53(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE53
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit54(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE54
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit55(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE55
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit56(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE56
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit57(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE57
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit58(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE58
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit59(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE59
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit60(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE60
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=NONE" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=WRITE, DENY=READ
def testShareUnit61(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE61
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit62(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE62
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit63(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE63
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit64(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE64
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit65(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE65
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit66(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE66
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit67(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE67
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit68(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE68
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit69(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE69
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit70(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE70
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit71(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE71
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit72(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE72
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=READ" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=WRITE, DENY=WRITE
def testShareUnit73(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE73
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit74(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE74
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit75(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE75
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit76(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE76
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit77(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE77
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit78(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE78
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit79(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE79
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit80(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE80
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit81(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE81
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit82(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE82
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit83(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE83
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit84(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE84
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=WRITE" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=WRITE, DENY=BOTH
def testShareUnit85(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE85
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit86(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE86
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit87(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE87
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit88(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE88
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit89(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE89
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit90(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE90
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit91(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE91
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit92(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE92
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit93(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE93
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit94(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE94
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit95(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE95
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit96(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE96
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=WRITE, deny=BOTH" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=BOTH, DENY=NONE
def testShareUnit97(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE97
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit98(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE98
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit99(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE99
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit100(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE100
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit101(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE101
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit102(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE102
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit103(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE103
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit104(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE104
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit105(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE105
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit106(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE106
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit107(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE107
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit108(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE108
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=NONE" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=BOTH, DENY=READ
def testShareUnit109(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE109
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit110(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE110
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit111(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE111
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit112(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE112
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit113(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE113
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit114(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE114
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit115(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE115
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit116(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE116
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit117(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE117
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit118(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE118
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit119(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE119
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit120(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE120
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=READ" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=BOTH, DENY=WRITE
def testShareUnit121(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE121
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit122(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE122
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit123(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE123
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit124(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE124
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit125(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE125
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit126(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE126
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit127(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE127
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit128(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE128
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit129(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE129
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit130(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE130
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit131(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE131
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit132(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE132
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=WRITE" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

# Current ACCESS=BOTH, DENY=BOTH
def testShareUnit133(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE133
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('READ', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit134(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE134
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('READ', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit135(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE135
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('READ', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit136(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE136
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('READ', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit137(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE137
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('WRITE', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit138(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE138
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('WRITE', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit139(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE139
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('WRITE', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit140(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE140
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('WRITE', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit141(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE141
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('BOTH', 'NONE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit142(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE142
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('BOTH', 'READ'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit143(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE143
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('BOTH', 'WRITE'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit144(t, env):
  """OPEN conflicting with previous share
    FLAGS: all share
    DEPEND: MKFILE
    CODE: SHARE144
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  check(res, NFS4ERR_SHARE_DENIED,
        "Trying to open a file with access=%s, deny=%s "
        "that was already opened with access=BOTH, deny=BOTH" % ('BOTH', 'BOTH'))
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit201(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: MKFILE
    CODE: SHARE201
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit202(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi
    DEPEND: MKFILE
    CODE: SHARE202
    """
  c = env.c1
  c.init_connection()
  file = c.homedir + [t.code]
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  sleeptime = _waitForOtherClient(c, env)
  env.sleep(sleeptime, "Waiting for %d seconds" % (sleeptime))

def testShareUnit301(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi
    DEPEND: MKFILE
    CODE: SHARE301
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  sleeptime = _waitForOtherClient(c, env)
  env.sleep(sleeptime, "Waiting for %d seconds" % (sleeptime))

def testShareUnit302(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi
    DEPEND: MKFILE
    CODE: SHARE302
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  sleeptime = _waitForOtherClient(c, env)
  env.sleep(sleeptime, "Waiting for %d seconds" % (sleeptime))

def testShareUnit303(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi
    DEPEND: MKFILE
    CODE: SHARE303
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  sleeptime = _waitForOtherClient(c, env)
  env.sleep(sleeptime, "Waiting for %d seconds" % (sleeptime))

def testShareUnit304(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi
    DEPEND: MKFILE
    CODE: SHARE304
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  sleeptime = _waitForOtherClient(c, env)
  env.sleep(sleeptime, "Waiting for %d seconds" % (sleeptime))

def testShareUnit305(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi
    DEPEND: MKFILE
    CODE: SHARE305
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  fh, stateid = c.create_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  sleeptime = _waitForOtherClient(c, env)
  env.sleep(sleeptime, "Waiting for %d seconds" % (sleeptime))

def testShareUnit401(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE401
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s " % ('READ', 'NONE'))

def testShareUnit402(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE402
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s " % ('WRITE', 'NONE'))

def testShareUnit403(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE403
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s " % ('WRITE', 'WRITE'))

def testShareUnit404(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE404
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  check(res, NFS4_OK,
        "Trying to open a file with access=%s, deny=%s " % ('READ', 'READ'))

def testShareUnit405(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE405
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  checklist(res, [NFS4ERR_SHARE_DENIED, NFS4ERR_ACCESS],
        "Trying to open a file with access=%s, deny=%s " % ('READ', 'NONE'))

def testShareUnit406(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE406
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  checklist(res, [NFS4ERR_SHARE_DENIED, NFS4ERR_ACCESS],
        "Trying to open a file with access=%s, deny=%s " % ('WRITE', 'WRITE'))

def testShareUnit407(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE407
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  checklist(res, [NFS4ERR_SHARE_DENIED, NFS4ERR_ACCESS],
        "Trying to open a file with access=%s, deny=%s " % ('WRITE', 'NONE'))

def testShareUnit408(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_multi2
    DEPEND:
    CODE: SHARE408
    """
  c = env.c1
  c.init_connection()
  a = ['MULTISHARE']
  file = c.homedir + a
  
  res = c.open_file('newowner', file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  checklist(res, [NFS4ERR_SHARE_DENIED, NFS4ERR_ACCESS],
        "Trying to open a file with access=%s, deny=%s " % ('READ', 'READ'))

def testShareUnit501(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE501
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit502(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE502
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit503(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE503
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit504(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE504
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit505(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE505
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit506(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE506
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit507(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE507
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit508(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE508
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit509(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE509
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit510(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE510
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit511(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE511
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit512(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE512
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  
  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit601(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE601
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_NONE)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit602(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE602
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_READ)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit603(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE603
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_WRITE)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit604(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE604
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_READ, deny=OPEN4_SHARE_DENY_BOTH)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit605(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE605
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_NONE)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit606(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE606
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_READ)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit607(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE607
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_WRITE)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit608(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE608
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_WRITE, deny=OPEN4_SHARE_DENY_BOTH)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit609(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE609
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_NONE)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit610(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE610
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_READ)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit611(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE611
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_WRITE)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

def testShareUnit612(t, env):
  """OPEN conflicting with previous share
    FLAGS: share_release
    DEPEND: 
    CODE: SHARE612
    """
  c = env.c1
  c.init_connection()
  a = ['share_reservation_test_file']
  file = env.opts.path[:-1] + a 
   
  fh, stateid = c.open_confirm(t.code, file, access=OPEN4_SHARE_ACCESS_BOTH, deny=OPEN4_SHARE_DENY_BOTH)
  _informFileOpened(c, env)
  _waitForNextStep(c, env)

  res = c.close_file(t.code, fh, stateid)
  check(res, msg="CLOSE a file")

