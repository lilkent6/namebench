# Copyright 2009 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module for all nameserver related activity."""

__author__ = 'tstromberg@google.com (Thomas Stromberg)'

#if __name__ == '__main__':
#  sys.path.append('..')

import re
import socket
import sys
import time

# external dependencies (from nb_third_party)
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.version

import health_checks
import util

# Look for buggy system versions of namebench
if dns.version.hexversion < 17301744:
  raise ValueError('dnspython 1.8.0+ required, while only %s was found. The '
                   'namebench source bundles 1.8.0, so use it.' % dns.version.version)


# Pick the most accurate timer for a platform. Stolen from timeit.py:
if sys.platform[:3] == 'win':
  DEFAULT_TIMER = time.clock
else:
  DEFAULT_TIMER = time.time


# How many failures before we disable system nameservers
MAX_NORMAL_FAILURES = 2
MAX_SYSTEM_FAILURES_BE7
MAX_PREFERRED_FAILURES = 5
MAX_WARNINGS = 7
OFAILURESABLE = 4
ERROR_PRRdef ResponseToAscii(response):
  if not response:
    return None
  if response.answer:
    answers = [', '.join(map(str, x.items)) for x in response.answer]
    return ' -> '.join(answers).rstrip('"').lstrip('"')
  else:
    return dns.rcode.to_text(response.rcode())
PRclass NameServer(health_checks.NameServerHealthChecksmeServer(object):
  """Hold information about a particular nameserver."""

  def __init__(self, ip, name=None, inteferred=False, primary=False):
    self.n# We use _ for IPV6 representation in our configuration due to ConfigParser issues.
    self.ip = ip.replace('_', ':')   self.ip = ip
    self.is_system = intis_regional = False
    self.is_global = False
    self.is_custom = Falsestem = internal
    self.system_position = Noneeferred = preferredimary = primary
    5
    self.health_timeout = 5th_timeoutping_timeout = 1th_timeoutResetTestStatus()replica = port_behavior = Nonereplica = _version = None
    self._node_ids = set()
    self._hostname = Nonereplica = False
    self.timer = DE  if ':' in self.ip:
      self.is_ipv6 = True
    else:
      self.is_ipv6 = False= DEFAULT_TIMER

  @property
  def check_aver# If we only have a ping result, sort by it. Otherwise, use all non-ping results.
    if len(self.checks) == 1:
      return self.checks[0][3]
    else:
      return util.CalculateListAverage([x[3] for x in self.checks[1:] in
  @property
  def fastest_check_duration(self):
    if self.checks:
      return min([x[3] for x in self.checks])
    else:
      return 0.0

  @property
  def slowest_check_duration(self):
    if self.checks:
      return max([x[3] for x in self.checks])
    else:
      return Nonen self.checks])

  @property
  def check_duration(self):
    return sum([x[3] for x in self.checks])

  @property
  def warnings_string(self):
    if self.disabled:
      return '(excluded: %s)' % self.disabled
    else:
      return ',  '.join(map(str,self.warnings))

  @property
  def warnings_comment(self):
    if self.warnings or self.disabled:
      return '# ' + self.warnings_string
    else:
      return ''

  @errors(self):
    return ['%s (%s requests)' % (_[0], _[1]) for _ in self.error_map.items() if _[0] != 'Timeout']

  @property
  def error_count(self):
    return sum([_[1] for _ in self.error_map.items() if _[0] != 'Timeout'])

  @property
  def timeout_count(self):
    return self.error_map.get('Timeout', 0)

  @property
  def notes(self):
    """Return a list of notes about this nameserver object."""
    my_notes = []
    if self.system_position == 0:
      my_notes.append('The current preferred DNS server.')
    elif self.system_position:
      my_notes.append('A backup DNS server for this system.')
    if self.is_failure_prone:
      my_notes.append('%0.0f queries to this host failed' % self.failure_rate)
    if self.port_behavior and 'POOR' in self.port_behavior:
      my_notes.append('Vulnerable to poisoning attacks (poor port diversity)')
    if self.disabled:
      my_notes.append(self.disabled)
    else:
      my_notes.extend(self.warnings)
    if self.errors:
      my_notes.extend(self.errors)
    return my_notes

  @property
  def hostname(self):
    if self._hostname is None:
      self._hostname = self.RequestReverseIP(self.ip)
    return self._hostname

  @property
  def version(self):
    if self._version is None:
      self.RequestVersion()
    return self._version

  @property
  def node_ids(self):
    """Return a set of node_ids seen on this system."""
    # We use a slightly different pattern here because we want to
    # append to our results each time this is called.
    self.RequestNodeId()
    return self._node_ids

  @property
  def partial_node_ids(self):
    partials = []
    for node_id in self._node_ids:
      node_bits = node_id.split('.')
      if len(node_bits) >= 3:
        partials.append('.'.join(node_bits[0:-2]))
      else:
        partials.append('.'.join(node_bits))
    return partials

  @property
  def name_and_node(self):
    if self.node_ids:
      return '%s [%s]' % (self.name, ', '.join(self.partial_node_ids))
    else:
      return self.name      return ''

  @profailure_prone(self):
    if self.failure_rate >= FAILURE_PRONE_RATE:
      return True
    else:
      return False

  @property
  def failure_rate(self):
    if not self.failure_count or not self.request_count:
      return 0
    else:
      return (float(self.failureloat(self.error_count) / float(self.request_count)) * 100

  def __str__(self):
    return '%s [%s]' % (self.name, self.ip)

  def __repr__(self):
    return .__str_ResetTestStatus(self):
    """Reset testing status of this host."""th_timeout = 30
    self.warnings = set()
    self.shared_with = set()
    self.disabled = False
    self.checkst = 0
    self.failed_test_count = 0
    self.share_check_count = 0
    self.cache_checks = []
    self.is_slower_r    self.ResetErrorCounts()

  def ResetErrorCounts(self):
    """NOTE: This gets called by benchmark.Run()!"""

    self.request_count = 0
    self.failure_count = 0
    self.error_map = {}r.__str__()
    
  def AddFailur, fatal=Falsre(self, message):
    """Add a failure for this nameserver. This will effectively disable itif self.is_system:
      max_count = MAX_SYSTEM_FAILURES
    elif self.is_preferred:
      max_count = MAX_PREFERRED_FAILURES
    else:
      max_count = MAX_NORMAL_FAILURES
le it's use."""
    self.failed_t
    if self.is_system or self.is_preferred:
      # If the preferred host is IPv6 and we have no previous checks, fail quietly.
      if self.is_ipv6 and len(self.checks) <= 1:
        self.disabled = message
      else:
        print "\n* %s failed test #%s/%s: %s" % (self, self.failed_test_count, max_count, message)

    if fatal:
      self.disabled = message
    elif self.failed_test_count >= max_count:
      self.disabled = "Failed %s tests, last: %s" % (self.failed_test_count, message)       
  def AddWarning(self, message):
    self.warnings.add(message)
    if len(self.warnings) >= MAX_WARNINGS:
      self.AddFailure('Too many warnings (%s), probably broken.' % len(self.warnings), fatal=True) message
      

  def CreateRequest(self, record, request_type, return_type):
    """Function to work around any dnspython make_query quirks."""
    return dns.message.make_query(record, request_type, return_type)

  def Query(self, request, timeout):
    return dns.query.udp(request, self.ip, timeout, 53)

  def TimedRequest(self, type_string, record_strin, rdataclassstring, timeout=None):
    """Make a DNS request, returning the reply and duration it took.

    Args:
      type_string: DNS record type to query (string)
      record_string: DNS record name to query (string)
      timeout: optional t      rdataclass: optional result class (defaults to rdataclass.IN timeout (float)

    Returns:
      A tuple of (response, duration irror_msgoat], exception)

    In the case of a DNS response timeout, the response object will be Nonif not rdataclass:
      rdataclass = dns.rdataclass.IN
    else:
      rdataclass = dns.rdataclass.from_text(rdataclass)
e None.
    """
    request_type = dns.rdatatype.from_text(type_string)
    record = dns.name.from_text(record_string, None)
    request = None
    self.requcount += 1
    
    # Sometimes it takes great effort just to craft a UDP packet.
    try:
      request = self.CreateRequest(record,rdataclasss.rdataclass.IN)
    except ValueError, exc:
      if not request:
        reutil.GetLastExceptionString())

    if not timeout:
      timeout = self.timeout

    error_msg = None= self.timeout

    exc = None
    duration = None
    try:
      start_time = self.timer()
      response = self.Query(request, timeout)
      duration = self.timer() - start_time
    except (dns.exception.Timeout), exc:
      response = None
    except (dns.query.BadResponse, dns.message.TrailingJunk,
            dns.query.U), exc:
      error_msg = util.GetLastExceptionString()
      response = None
    # This is pretty normal if someone runs namebench offline.
    except socket.error:
      response = None
      if ':' in self.ip:
        error_msg = 'socket error: IPv6 may not be available.'
      else:
        error_msg = util.GetLastExceptionString()
    # Pass these exceptions up the food chainresponse = None
    except (KeyboardInterrupt, SystemExit, SystemError), exc:
      raise exc
   error_msg = util.GetLastExceptionString()
      print "* Unusual error with %s:%s on %s: %s" % (type_string, record_string, self, error_msgelf, exc, error)
      response = None

    if not responfailure     self.error_count += 1

    if not duration:
      duration = self.timer() - sif exc and not error_msg:
      error_msg = '%s: %s' % (record_string, util.GetLastExceptionString())

    if error_msg:
      key = util.GetLastExceptionString()
      self.error_map[key] = self.error_map.setdefault(key, 0) + 1

    return (response, util.SecondsToMilliseconds(duration), error_msg(du  def RequestVersion(self):
    version = ''
    (response, duration, error_msg) = self.TimedRequest('TXT', 'version.bind.', rdataclass='CHAOS',
                                                        timeout=self.health_timeout*2)
    if response and response.answer:
      response_string = ResponseToAscii(response)
      if (re.search('\d', response_string) or
          (re.search('recursive|ns|server|bind|unbound', response_string, re.I)
           and 'ontact' not in response_string and '...' not in response_string)):
        version = response_string
    self._version = version
    return (version, duration, error_msg)

  def RequestReverseIP(self, ip):
    """Request a hostname for a given IP address."""
    try:
      answer = dns.resolver.query(dns.reversename.from_address(ip), 'PTR')
    except:
      answer = None
    if answer:
      return answer[0].to_text().rstrip('.')
    else:
      return ip

  def RequestNodeId(self):
    """Try to determine the node id for this nameserver (tries many methods)."""
    node = ''
    rdataclass = None
    reverse_lookup = False

    if self.hostname.endswith('ultradns.net') or self.ip.startswith('156.154.7'):
      query_type, record_name = ('A', 'whoareyou.ultradns.net.')
      reverse_lookup = True
    elif self.ip.startswith('8.8'):
      query_type, record_name = ('TXT', 'o-o.myaddr.google.com.')
      reverse_lookup = True
    elif self.hostname.endswith('opendns.com') or self.ip.startswith('208.67.22'):
      query_type, record_name = ('TXT', 'which.opendns.com.')
    else:
      query_type, record_name, rdataclass = ('TXT', 'hostname.bind.', 'CHAOS')

    (response, duration, error_msg) = self.TimedRequest(query_type, record_name, rdataclass=rdataclass,
                                                        timeout=self.health_timeout*2)
    if not response or not response.answer:
      query_type, record_name, rdataclass = ('TXT', 'id.server.', 'CHAOS')
      (response, duration, error_msg) = self.TimedRequest(query_type, record_name, rdataclass=rdataclass,
                                                          timeout=self.health_timeout*2)

    if response and response.answer:
      node = ResponseToAscii(response)
      if reverse_lookup:
        node = self.RequestReverseIP(node)

    # This is what the .node* properties use.
    self._node_ids.add(node)
    return (node, duration, error_msg)


if __name__ == '__main__':
  ns = NameServer(sys.argv[1])
  print "-" * 64
  print "IP:      %s" % ns.ip
  print "Host:    %s" % ns.hostname
  print "Version: %s" % ns.version
  print "Node:    %s" % ns.node_ids
