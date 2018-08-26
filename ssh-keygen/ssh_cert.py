"""Utility to generate ssh identities and certificates.

Usage:
%(name)s all|<users>
"""

import commands
import getopt
import os
import pwd
import re
import shutil
import socket
import stat
import sys

# For RSA, 2048 bits should currently be sufficient for most purposes.
BIT_LENGTH = 2048

# Location of user home directories.
USER_DIR = '/user'

# Usernames.
USERNAMES = ['vasanths']

# Verbose on/off.
VERBOSE = False

# Test mode on/off.
TEST = False

# SSH key type:'rsa1' for protocol v.1 and 'rsa' or 'dsa' for protocol v.2
SSH_KEY_TYPE = 'rsa'

# Permissions
READONLY = stat.S_IRUSR + stat.S_IRGRP + stat.S_IROTH
WORLD_READABLE = READONLY + stat.S_IWUSR
OWNER_ONLY = stat.S_IRUSR + stat.S_IWUSR
EXECUTABLE_DIR = READONLY + stat.S_IXUSR + stat.S_IXGRP + stat.S_IXOTH
OWNER_ONLY_DIR = OWNER_ONLY + stat.S_IXUSR

# Regular expression for key matches.
SSH2_RSA_KEY_MATCH_RE = re.compile(r'^\s*(ssh-rsa) (\S+) (.*)$')

# shell return codes.
SUCCESS = 0
FAILURE = 1
BAD_ARG = 2


def GetComment(key):
  """Get comment from an SSH protocol 2 public key.

  Args:
    key: public key string (str)

  Returns:
    comment
  """
  match = SSH2_RSA_KEY_MATCH_RE.match(key)
  if not match:
    return None
  return match.group(3)


def GetHostname():
  """Return the hostname of this machine."""
  return socket.gethostname()


def RunCommand(cmd):
  """Run a command locally.

  Args:
    cmd: Command to run (string)
  Returns:
    stderr, stdout
  Throws:
    EnvironmentError: If cmd failed to execute properly.
  """
  (status, output) = commands.getstatusoutput(cmd)
  if status != 0:
    raise EnvironmentError('Error running: %s - (%s) %s' % (cmd, status, output))
  return (status, output)


class SSHIdentity(object):
  """A ssh public/private identity"""
  _private_perms = stat.S_IRUSR
  _public_perms = READONLY

  def __init__(self, user, path, bit_length):
    """Initialize ssh identity.

    Args:
      user: Username that should exist in comment (string).
      path: Path name to private identity file (string).
      bit_length: (int) Number of bits in the key being created
    """
    self._prv_file = path
    self._pub_file = '%s.pub' % path
    self._user = user
    self._bit_length = bit_length

    # Find key comment.
    self._keyid = '%s@%s' % (user, GetHostname())
    print self._keyid

  def PrivateFile(self):
    """Return path to private key file."""
    return self._prv_file

  def PublicFile(self):
    """Return path to public key file."""
    return self._pub_file

  def KeyID(self):
    """Return key id (comment)."""
    return self._keyid

  def Exists(self):
    """True if the private identity file exists."""
    return os.path.isfile(self._prv_file)

  def PublicExists(self):
    """True if the public key file exists."""
    return os.path.isfile(self._pub_file)

  def ReadPublicKey(self):
    """Return public key string."""
    f = open(self._pub_file, 'r')
    lines = f.readlines()
    f.close()
    if not lines:
      return None
    return lines[0].strip()

  def ReadComment(self):
    """Return comment of public key file."""
    public_key = self.ReadPublicKey()
    if not public_key:
      return None
    return GetComment(public_key)

  def IsValid(self):
    """Test if identity is valid.

    Validity is based on existence of both the private and public identity
    files and whether the comment is proper. Note that if a machine name is
    changed the keys will be regenerated. During this interval, the local key
    will not exist in authorized keys.

    Returns:
      True if identity is valid.
    """
    if not self.Exists():
      print 'Missing private key file: ', self._prv_file
      return False
    if not self.PublicExists():
      print 'Missing public key file: ', self._pub_file
      return False

    # Use ssh-keygen -y to extract the public key from the private key file.
    (status, public_key) = RunCommand('ssh-keygen -y -f %s' % self._prv_file)
    if status != 0:
      print 'Failed to extract public key from %r' % self._prv_file
      return False

    my_public_key = self.ReadPublicKey()
    comment = GetComment(my_public_key)
    if comment != self._keyid:
      print 'Bad comment: %r should be %r' % (comment, self._keyid)
      return False

    if '%s %s' % (public_key, self._keyid) != my_public_key:
      print 'Public key file does not match private key'
      return False

    return True

  def CopyTo(self, identity_path):
    """Copy current identity to another location.

    Args:
      identity_path: Path to new identity file.
    """
    print 'inside CopyTo'
    saved_key = SSHIdentity(self._user, identity_path, self._bit_length)
    private = saved_key.PrivateFile()
    perms = self._private_perms
    print private
    _MakeFile(private, 'root:root', perms, src=self.PrivateFile())

    public = saved_key.PublicFile()
    perms = self._public_perms
    print public
    _MakeFile(public, 'root:root', perms, src=self.PublicFile())

  def Generate(self):
    """Generate new identity."""
    # Temporary key file names.
    tmp_prv = '%s_tmp' % self._prv_file
    tmp_pub = '%s.pub' % tmp_prv

    # Remove old/invalid files.
    for file in [tmp_prv, tmp_pub, self._prv_file, self._pub_file]:
      if os.path.exists(file):
        os.remove(file)

    # Generate SSH key files.
    keygen_cmd = ('ssh-keygen -b %d -f %s -N "" -C %s -t %s' %
                  (self._bit_length, tmp_prv, self._keyid, SSH_KEY_TYPE))
    RunCommand(keygen_cmd)
    shutil.move(tmp_prv, self._prv_file)
    shutil.move(tmp_pub, self._pub_file)
    print 'finished generating new identities'


def CreateSSHIdentity(user, path, bit_length):
  """Factory function for SSHIdentity, used for mock injection."""
  return SSHIdentity(user, path, bit_length)


def _MakeDir(dir, owner, perm):
  """Create directory if it does not exist and set attributes.

  Args:
    dir: Directory to create (string).
    owner: Owner (string) - i.e. 'user:group'.
    perm: Permission (string) - i.e. '777'.
  """
  if not os.path.isdir(dir):
    os.makedirs(dir)
  os.chmod(dir, perm)

  user, _ = owner.split(':')
  print user
  uid = pwd.getpwnam(user)[2]
  os.chown(dir, uid, -1)  # Tells os.chown to not specify a gid.


def _MakeFile(file, owner, perm, contents=None, src=None):
  """Create a file.

  Args:
    file: File to create (string).
    owner: Owner (string) - i.e. 'user:group'.
    perm: Permission (string) - i.e. '777'.
    contents: Optional contents to initialize (string).
    src: Optional source file to copy from (string).
  """
  global TEST

  if not os.path.isfile(file):
    open(file, 'w').close()

  if not TEST and contents is not None:
    f = open(file, 'w')
    f.write(contents)
    f.close()
  elif src:
    RunCommand('cp -f -p %s %s' % (src, file))

  user, _ = owner.split(':')
  uid = pwd.getpwnam(user)[2]
  os.chown(file, uid, -1)  # Tells os.chown to not specify a gid.
  os.chmod(file, perm)


def BackupRootKey(root_key, ssh_dir):
  """Make necessary backups of root_key."""
  if root_key.Exists() and root_key.IsValid():
    # Save current unique identity.
    print 'Saving current identity'
    root_key.CopyTo(os.path.join(ssh_dir, 'identities', 'prv_identity'))

  elif root_key.Exists() and not root_key.IsValid():
    # If there is an existing identity then save it as an alternate identity
    # for backwards compatibility.
    print 'Saving current non-standard root identity'
    root_key.CopyTo(os.path.join(ssh_dir, 'identities', 'saved'))


def GenerateRootKeys(bit_length, force=False):
  """Generate keys for root.

  Args:
    bit_length: no.of.bits to create.
    force: Regenerate keys even if already present (bool).
  """
  print 'generating root keys'
  # Create ssh dir.
  ssh_dir = '/root/.ssh'
  _MakeDir(ssh_dir, 'root:root', OWNER_ONLY_DIR)
  print 'finished making dir as root'
  # Generate unique root identity.
  identity = os.path.join(ssh_dir, 'identity')
  key = CreateSSHIdentity('root', identity, bit_length)

  if force or not key.IsValid():
    BackupRootKey(key, ssh_dir)
    print 'Generating key for root'
    key.Generate()

  # Create random seed.
  random_seed = os.path.join(ssh_dir, 'random_seed')
  _MakeFile(random_seed, 'root:root', OWNER_ONLY)

  # Make sure known hosts is writable.
  known_hosts = os.path.join(ssh_dir, 'known_hosts')
  _MakeFile(known_hosts, 'root:root', WORLD_READABLE)


def GenerateUserSSHFiles(user):
  """Generate SSH folders and files for user.

  Args:
    user: User account to create (string).
  """
  # Create home dir.
  home_dir = os.path.join(USER_DIR, user)
  print 'creating home dir'
  _MakeDir(home_dir, 'root:root', EXECUTABLE_DIR)

  # Create ssh dir.
  ssh_dir = os.path.join(home_dir, '.ssh')
  print 'creating ssh dir'
  _MakeDir(ssh_dir, 'root:root', EXECUTABLE_DIR)

  # Create writable bash history.
  bash_history = os.path.join(home_dir, '.bash_history')
  print 'creating bash history'
  _MakeFile(bash_history, '%s:prod' % user, WORLD_READABLE)

  # Create bashrc.
  bashrc = os.path.join(home_dir, '.bashrc')
  if not os.path.exists(bashrc):
    _MakeFile(bashrc, 'root:root', WORLD_READABLE, src='/etc/skel/.bashrc')

  # Create ssh identities dir.
  identities_dir = os.path.join(ssh_dir, 'identities')
  _MakeDir(identities_dir, 'root:root', EXECUTABLE_DIR)

  # Create writable ssh agent file.
  agent_env = os.path.join(home_dir, '.env.ssh-agent')
  _MakeFile(agent_env, '%s:root' % user, WORLD_READABLE)

  # Create random seed.
  random_seed = os.path.join(ssh_dir, 'random_seed')
  _MakeFile(random_seed, '%s:root' % user, OWNER_ONLY)

  print 'completed with GeneratingUserSSHFiles'


def BackupUserKey(key, ssh_dir):
  """If keys exists and is valid, make a backup at identities/prv_identity."""
  if key.Exists() and key.IsValid():
    print 'Saving current identity'
    key.CopyTo(os.path.join(ssh_dir, 'identities', 'prv_identity'))


def GenerateUserKeys(user, bit_length, force=False):
  """Generate keys for specified user.

  Args:
    user: User account to create (string).
    bit_length: (int) Number of bits in the key being created
    force: Regenerate keys even if already present (bool).
  """
  print 'entering GenerateUserKeys'
  ssh_dir = os.path.join(USER_DIR, user, '.ssh')
  print ssh_dir
  key = CreateSSHIdentity(user, os.path.join(ssh_dir, 'identity'), bit_length)
  print key
  if force or not key.IsValid():
    BackupUserKey(key, ssh_dir)
    print 'Generating key for %s' % user
    key.Generate()


def GenerateCert(users, path, bit_length):
  """Generate Cert.

  Args:
    users: User account to create (string).
    path: Private key path.
    bit_length: (int) Number of bits in the key being created.

  Returns:
    (str) Contents of 'certificate'
  """
  print 'entering GenerateCert'
  del bit_length
  for user in users:
    key_id = '%s@%s' % (user, GetHostname())
    path = os.path.join(USER_DIR, user, '.ssh', 'identity')
  expiry = '+365d'
  pub_path = '%s.pub'% path
  certgen_cmd = ('ssh-keygen -s %s -I %s -V %s %s' %
                 (path, key_id, expiry, pub_path))
  (_, _) = RunCommand(certgen_cmd)
  cert_path = '%s-cert.pub'% path
  with open(cert_path, 'r') as fd:
    contents = fd.read()
  print contents
  return contents


def GenerateKeys(users, bit_length, force=False):
  """Generate keys.

  Args:
    users: Users to create keys for.
    bit_length: (int) Number of bits in the key being created
    force: Regenerate keys even if already present (bool).
  """
  # Test for ssh version.
  for user in users:
    print 'Checking keys for %s' % user
    if user == 'root':
      GenerateRootKeys(bit_length, force=force)
    else:
      GenerateUserSSHFiles(user)
      GenerateUserKeys(user, bit_length, force=force)


def Usage(msg=''):
  """Print out usage information.

  Args:
    msg: string - optional exit error message string

  Returns:
    bad_arg
  """
  print __doc__
  if msg:
    sys.stderr.write('\nERROR: %s\n' % msg)
  return BAD_ARG


def BuildUserList(requested_users):
  """Returns a user list ready for GenerateKeys."""
  if len(requested_users) == 1 and requested_users[0] == 'all':
    return USERNAMES + ['root']
  print requested_users
  return requested_users


def GetPublickey():
  """Check if Public key has already been created.

  Returns:
    bool: If public key is present, return True.
  """
  ssh_conf_path = os.path.expanduser('~/.ssh')
  public_key_path = os.path.join(ssh_conf_path, 'identity.pub')
  private_key_path = os.path.join(ssh_conf_path, 'identity')

  has_keypair = os.path.isfile(public_key_path) and \
      os.path.isfile(private_key_path)

  if has_keypair:
    print 'keypair found, using it'
  return True


def main(args):
  force = False
  bit_length = BIT_LENGTH

  print 'hello main'
  (optlist, args) = getopt.getopt(
      args, ' ', ['verbose', 'test', 'force', 'bit_length='])
  for flag, value in optlist:
    if flag == '--verbose':
      VERBOSE = True
    elif flag == '--test':
      TEST = True
    elif flag == '--force':
      force = True
    elif flag == '--bit_length':
      try:
        bit_length = int(value)
      except ValueError:
        return Usage('bit_length, must be an integer')

  users = args
  if not users:
    return Usage()

  try:
    if GetPublickey():
      print 'key already present'
      GenerateCert(BuildUserList(users), path=None, bit_length=None)
    else:
      GenerateKeys(BuildUserList(users), bit_length, force=force)
      print 'Generating Keys has been completed.'
      GenerateCert(BuildUserList(users), path=None, bit_length=None)
  except EnvironmentError, e:
    print >> sys.stderr, 'Error: %s' % str(e)
    return FAILURE

  return SUCCESS


if __name__ == '__main__' :
  main(sys.argv[1:])
