import unittest
import os
import shutil
import stat

import mox

from absl import flags

# Useful constants
from .ssh_cert import READONLY
from .ssh_cert import WORLD_READABLE
from .ssh_cert import OWNER_ONLY
from .ssh_cert import EXECUTABLE_DIR
from .ssh_cert import OWNER_ONLY_DIR

import ssh_cert

FLAGS = flags.FLAGS

# Public key for testdata/testkey
TEST_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDt8Ci0mAvvgN0dVNsjhDu4+jHDKHwZ/nKemE"
    "PKY1QO3dSi2z2AKiF59q1JnOauf3yQgGe4p7y+ETBfSvN7qAyJXSdqqV3BCFGBg3oQaX3ur0Oc"
    "qCtQqhqCl7F6cnYe8n0k9ADIbj4rIGb8UMxrL1YV79S/bqqRj/OPc88ZqFtc2A6NFpoBZthEPA"
    "FzPghzFRkyTkc2lGjGQtyWZEoa5aaogOhsiyOGIyt1eghGEYi1C/AoCg2fotOqgYbmZaIpvETm"
    "maB1SqMEVBrt31kh3QYhfvdPBobH3LF8acCrHM/KepHbQQ88ZQSCLzD5g/eL4DaU5WK8VSD5Jj"
    "TN8crBC+gp tester@test.com")

TEST_DATA_PATH = "/Users/vasanths/Desktop/ssh-keygen/testdata"


def _CreateTestKeyfile(key):
  """Given filename 'key', creates a copy of it and returns the path.

  Specifically, the copy only has the owner read/write flags set. This is
  due to ssh-keygen complaining if there is access outside of the owner.

  Args:
    key: The keyfile, located in testdata_path.

  Returns:
    A path to the copy of key.
  """
  source_key = os.path.join(FLAGS.test_srcdir, TEST_DATA_PATH, key)
  test_key = os.path.join(FLAGS.test_tmpdir, key)
  shutil.copyfile(source_key, test_key)
  shutil.copyfile(source_key + ".pub", test_key + ".pub")
  os.chmod(test_key, stat.S_IRUSR | stat.S_IWUSR)
  return test_key


class SSHIdentityTest(mox.MoxTestBase):
  """Unittests for ssh_cert.SSHIDentityTest.

  These use testdata/testkey and testdata/testkey.pub
  """
  user = "tester"
  testcomment = "tester@test.com"

  def setUp(self):
    super(SSHIdentityTest, self).setUp()

    # ssh-keygen -k complains if the private keys can be accessed by anyone
    # other than the owner. This file creates a copy suitable for testing.
    # Failure to due this causes ssh-keygen to create a new key and prompt for a
    # password, breaking this test.
    self.good_key = _CreateTestKeyfile("testkey")
    self.bad_key = _CreateTestKeyfile("testkey_bad")
    self._bit_length = ssh_cert.BIT_LENGTH

    # Create an SSHIdentity for a test machine by stubbing out GetHostname
    self._old_GetHostname = ssh_cert.GetHostname
    ssh_cert.GetHostname = lambda: "test.com"
    self.identity = ssh_cert.SSHIdentity(self.user, self.good_key,
                                         self._bit_length)

  def tearDown(self):
    ssh_cert.GetHostname = self._old_GetHostname

  def testPrivateFile(self):
    self.assertEqual(self.good_key, self.identity.PrivateFile())

  def testPublicFile(self):
    self.assertEqual(self.good_key + ".pub", self.identity.PublicFile())

  def testKeyID(self):
    self.assertEqual(self.testcomment, self.identity.KeyID())

  def testExists(self):
    self.assertTrue(self.identity.Exists())
    self.assertTrue(self.identity.PublicExists())

  def testExists_False(self):
    no_key = "no_key_here"
    self.assertFalse(ssh_cert.SSHIdentity(self.user, no_key,
                                          self._bit_length).Exists())
    self.assertFalse(ssh_cert.SSHIdentity(
        self.user, no_key, self._bit_length).PublicExists())

  def testReadPublicKey(self):
    self.assertEqual(TEST_KEY, self.identity.ReadPublicKey())

  def testReadComment(self):
    self.assertEqual(self.testcomment, self.identity.ReadComment())

  def testIsValid_Good(self):
    self.assertTrue(self.identity.IsValid())

  def testIsValid_MissingPublicKey(self):
    self.mox.StubOutWithMock(os.path, "isfile")
    os.path.isfile(self.identity.PrivateFile()).AndReturn(True)
    os.path.isfile(self.identity.PublicFile()).AndReturn(False)

    self.mox.ReplayAll()
    self.assertFalse(self.identity.IsValid())

  def testIsValid_MissingPrivateKey(self):
    self.mox.StubOutWithMock(os.path, "isfile")
    os.path.isfile(self.identity.PrivateFile()).AndReturn(False)

    self.mox.ReplayAll()
    self.assertFalse(self.identity.IsValid())

  def testIsValid_BadComment(self):
    bad_identity = ssh_cert.SSHIdentity("really_bad_comment",
                                        self.good_key, self._bit_length)
    self.assertFalse(bad_identity.IsValid())

  def testIsValid_MismatchedPublicKey(self):
    bad_identity = ssh_cert.SSHIdentity(self.user, self.bad_key,
                                        self._bit_length)
    self.assertFalse(bad_identity.IsValid())

  def testCopyTo(self):
    """Test CopyTo by checking for a copy to testpath."""
    self.mox.StubOutWithMock(ssh_cert, "_MakeFile")
    key = "testpath"
    pubkey = key + ".pub"
    root = "root:root"
    id = self.identity
    mode = self.identity._private_perms
    ssh_cert._MakeFile(key, root, mode, src=id.PrivateFile())
    mode = self.identity._public_perms
    ssh_cert._MakeFile(pubkey, root, mode, src=id.PublicFile())

    self.mox.ReplayAll()
    self.identity.CopyTo(key)

  def testGenerate(self):
    user = "new_user"
    new_key = os.path.join(FLAGS.test_tmpdir, "new_key")
    if os.path.isfile(new_key):
      os.remove(new_key)

    # Should be no key yet
    ssh = ssh_cert.SSHIdentity(user, new_key, self._bit_length)
    self.assertFalse(ssh.Exists())

    ssh.Generate()
    self.assertTrue(ssh.Exists())
    self.assertTrue(ssh.IsValid())


class MainTest(mox.MoxTestBase):
  """Test the main function."""

  def setUp(self):
    mox.MoxTestBase.setUp(self)
    self.mox.StubOutWithMock(ssh_cert, "GenerateKeys")
    self.mox.StubOutWithMock(ssh_cert, "RunCommand")
    self.mox.StubOutWithMock(ssh_cert.getpass, "getuser")
    self._bit_length = ssh_cert.BIT_LENGTH

  def testBuildUserList(self):
    users = ["user"]
    self.assertEqual(users, ssh_cert.BuildUserList(users))

    users.append("user2")
    self.assertEqual(["user"], ssh_cert.BuildUserList(["user"]))

    self.assertEqual(
        set(ssh_cert.USERNAMES + ["root"]),
        set(ssh_cert.BuildUserList(["all"])))

  def testArgs(self):
    self.mox.ReplayAll()
    self.assertNotEqual(0, ssh_cert.main([]))

  def testSuccessWithForce(self):
    ssh_cert.getpass.getuser().AndReturn("root")
    users = ["user"]
    args = ["--force"] + users
    ssh_cert.GenerateKeys(users, self._bit_length, force=True)
    self.mox.ReplayAll()
    self.assertEqual(0, ssh_cert.main(args))

  def testGenerateKeysFailure(self):
    ssh_cert.getpass.getuser().AndReturn("root")
    users = ["user"]
    ssh_cert.GenerateKeys(users, self._bit_length,
                          force=False).AndRaise(EnvironmentError)
    self.mox.ReplayAll()
    self.assertNotEqual(0, ssh_cert.main(users))


if __name__ == '__main__':
  unittest.main()
