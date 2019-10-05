#!/usr/bin/python3 -u

import argparse
import getpass
import grp
import json
import os
import paramiko
import re
import select
import subprocess
import sys
import termcolor
import textwrap
import time
import traceback

socketcanTest = None

def print_err(string):
	global socketcanTest

	print(termcolor.colored(string, "red"))

	if socketcanTest.exit_on_error:
		os._exit(1)

class SocketCanNode:
	def __init__(self, can_if, role, hostname = "", username = "root"):
		self._can_if = can_if
		self._name = hostname if hostname else "localhost"
		self._role = role

		if hostname:
			self.setup_ssh(hostname, username)
		else:
			self.ssh = None

		if not self.run_if("-d /sys/class/net/" + can_if):
			print(can_if + " does not exist on " + self._name)
			sys.exit(1)

		driver = self.run("basename $(readlink -f /sys/class/net/" + self._can_if + "/device/driver)")
		print("driver of " + str(self) + " is " + driver.strip())
		self._is_venus = self.run_if('-d /etc/venus')
		if self._is_venus:
			print(hostname + " is a Venus device")
			self.venus_init()

		self.if_down()
		self.check_qdisc()

		try:
			self.get(["linkinfo", "info_data", "berr_counter", "rx"])
			self.has_error_counters = True
		except:
			self.has_error_counters = False

	def setup_ssh(self, hostname, username):
		print("Connecting to " + hostname + "...")
		self.ssh = paramiko.SSHClient()
		self.ssh.load_system_host_keys()
		self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		self.ssh.connect(hostname=hostname, username=username, timeout=10)
		self.ssh.invoke_shell()

	def if_down(self):
		print("Downing " + str(self))
		self.run("ip link set dev " + self._can_if + " down")
		self.update_if_details()

		state = self.poll(["operstate"], "DOWN")
		self.eq("should be down", state, "DOWN")
		print("")

	def if_up(self, bitrate = 250000, restart_ms = 0, tx_queue_len = 10):
		print("Up " + str(self))
		self.run("ip link set " + self._can_if + " txqueuelen " + str(tx_queue_len) +
				 " up type can bitrate " + str(bitrate) + " restart-ms " + str(restart_ms))
		self.update_if_details()

		state = self.poll(["linkinfo", "info_data", "state"], "ERROR-ACTIVE")
		self.eq("up state", state , "ERROR-ACTIVE")

		# wait for link up? USB device postpone that it seems..
		#state = self.poll(["operstate"], "UP")
		#self.eq("should be up", state, "UP")

		print("")

	""" Venus OS specific """
	def venus_init(self):
		print("Stopping all CAN-bus processes using " + str(self))
		self.run("svc -d /service/*" + self._can_if + "*")

	def check_qdisc(self):
		print("qdisc of " + str(self) + " is " + self._details["qdisc"])
		if self._details["qdisc"] == "fq_codel":
			print("fq_codel found on " + str(self))
			if self._is_venus:
				print("Please fix the device")
				sys.exit(1)
			print("Fixing it for you....")
			self.run("tc qdisc replace dev " + self._can_if + " root pfifo_fast")
			self.update_if_details()

	def __str__(self):
		return self._can_if + " on " + self._name

	### blocking call, will throw is exit code != 0 ###
	def run(self, command, timeout = 3, silent = False):
		if not silent:
			print(self._name + ":" + self._can_if + "$ " + command)
		if self.ssh:
			_stdin, stdout, _stderr = self.ssh.exec_command(command + " &2>1", timeout=timeout)
			ret = stdout.read().decode('utf-8')
			exit_code = stdout.channel.recv_exit_status()
			if exit_code != 0:
				raise subprocess.CalledProcessError(exit_code, command, ret)
			return ret

		return subprocess.check_output(["/bin/sh", "-c", command]).decode('utf-8')

	def run_parse_int(self, command):
		result = self.run(command)
		return int(result)

	def run_if(self, condition):
		cmd = 'if [ ' + condition + ' ]; then echo 1; else echo 0; fi'
		return self.run_parse_int(cmd)

	def update_if_details(self):
		result = self.run("ip -json -details -statistic link show " + self._can_if)
		# workaround for broken iproute2, see patch "ip: iplink_can.c: fix json formatting"
		result = re.sub(r'{state ([a-zA-Z0-9_-]+)', r'{\n"state": "\1",', result)
		self._details = json.loads(result)[0]
		#self.dump_details()

	""" helper for debugging """
	def dump_details(self):
		print(json.dumps(self._details, indent=4))

	def get(self, what):
		ret = self._details
		for id in what:
			ret = ret[id]
		return ret

	def send_msg(self):
		self.run("cansend " + self._can_if + " 123#1122334455667788")
		self.update_if_details()

	def send_stuff_msg(self):
		self.run("cansend " + self._can_if + " 7FF#FFFFFFFF")
		self.update_if_details()

	# note: needs a big txqueuelen!
	def cangen(self, n):
		self.run("cangen " + self._can_if + " -I i -D i -L 8 -g0 -p0 -n" + str(n))
		self.update_if_details()

	def poll(self, what, value, timeout = 1000):
		while timeout > 0:
			new_value = self.get(what)
			#print(new_value)
			if new_value == value:
				return value
			time.sleep(0.050)
			timeout -= 50
			self.update_if_details()

		# throw instead?
		return new_value

	def check_print(self, why, error=False):
		string = str(self) + " " + why
		if error:
			print_err(string)
		else:
			print(string)

	def eq(self, why, a, b):
		if a != b:
			self.check_print("!!! ERROR !!!: " + why + " " + str(a) + " != " + str(b), True)
			return

		self.check_print("OK: " + why + " " + str(a) + " == " + str(b))

	def eq_p(self, why, what, expected):
		value = self.get(what)
		self.eq(why, value, expected)

	def ge(self, why, a, b):
		if a < b:
			self.check_print("!!! ERROR !!!: " + why + " " + str(a) + " < " + str(b), True)
			return

		self.check_print("OK: " + why + " " + str(a) + " >= " + str(b))

	def ge_p(self, why, what, expected):
		value = self.get(what)
		self.ge(why, value, expected)
		return value

class CpuLoad:
	def __init__(self, node):
		self._node = node
		self.last_stat = self.get_stat()

	def diff(self, last, now):
		sum = 0
		ret = []
		for i in range(0, len(now)):
			ret.append(float(now[i] - last[i]))
			sum += ret[i]
		for i in range(0, len(now)):
			ret[i] /= sum
		return ret, sum

	def get_stat(self):
		line = self._node.run("head -n1 /proc/stat", silent = True)
		parts = re.split(r'\s+', line.strip())
		del parts[0]
		for i in range(0, len(parts)):
			parts[i] = int(parts[i])
		return parts

	def print(self, name, value):
		print(name + ": %.1f%%" % (value * 100), end="   ")

	def dump(self):
		now = self.get_stat()
		stat, _total = self.diff(self.last_stat, now)
		user = stat[0]
		nice = stat[1]
		system = stat[2]
		idle = stat[3]
		iowait = stat[4]
		irq = stat[5]
		softirq = stat[6]

		self.print("usr", user)
		self.print("nic", nice)
		self.print("sys", system)
		self.print("idle", idle)
		self.print("io", iowait)
		self.print("irq", irq)
		self.print("sirq", softirq)
		print("")

""" Background process which dumps socketcan traffic """
class BackgroundProcess:
	def __init__(self, node, cmd, get_pty=False):
		self._node = node
		self._buf = ""
		self.name = cmd[0]
		self._stopped = False

		print("Starting " + " ".join(cmd) + " on " + str(node))
		if node.ssh:
			transport = node.ssh.get_transport()
			self._session = transport.open_session()
			self._session.set_combine_stderr(True)
			# get a tty for line buffering, but also makes
			# it blocking it seems...
			if get_pty:
				self._session.get_pty()
			self._session.exec_command("exec " + " ".join(cmd))
		else:
			self.p = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)

		self.cpu_load = CpuLoad(node)
		self.cpu_dump_done = False

	def dump_cpuinfo_once(self):
		if self.cpu_dump_done:
			return
		self.cpu_load.dump()
		self.cpu_dump_done = True

	def close(self):
		print("Stopping " + self.name + " on " + str(self._node))
		if self._node.ssh:
			self._session.close()
		else:
			self.p.kill()

	def returncode(self):
		if self._node.ssh:
			if self._session.exit_status_ready():
				ret = self._session.recv_exit_status()
			else:
				return None
		else:
			if self.p.returncode is None:
				return None
			else:
				ret = self.p.returncode

		if not self._stopped:
			self._stopped = True
			print("\n" + self.name + " on " + str(self._node) + " stopped" + " (" + str(ret) + ")")

		return ret

	""" (intended to be a ) non blocking version to get or dump the output """
	def dump(self, silent = False):
		ret = ""
		if self._node.ssh:
			while self._session.recv_ready():
				ret += self._session.recv(4096).decode('utf-8')
		else:
			if self.p.stdout:
				os.set_blocking(self.p.stdout.fileno(), False)
				while True:
					line = self.p.stdout.read(4096)
					if line:
						ret += line #.decode('utf-8')
					else:
						break
		if not silent:
			print(ret, end='', flush=True)

		return ret

	""" read more from the ssh session to self._buf. return time left. """
	def read_more_ssh(self, timeout):
		start = time.perf_counter()
		fileno = self._session.fileno()
		readable, _writable, _exceptional = select.select([fileno], [], [], timeout)
		if not readable:
			return 0
		elapsed = time.perf_counter() - start
		if elapsed == 0:
			elapsed = 0.00001
		remaining = timeout - elapsed
		if remaining < 0:
			remaining = 0
		while self._session.recv_ready():
			self._buf += self._session.recv(4096).decode('utf-8')
		return remaining

	def read_more_process(self, timeout):
		start = time.perf_counter()
		readable, _writable, _exceptional = select.select([self.p.stdout], [], [], timeout)
		if not readable:
			return 0
		elapsed = time.perf_counter() - start
		if elapsed == 0:
			elapsed = 0.00001
		remaining = timeout - elapsed
		if remaining < 0:
			remaining = 0
		os.set_blocking(self.p.stdout.fileno(), False)
		while True:
			data = self.p.stdout.read(4096)
			self._buf += data
			if not data:
				break

		return remaining

	""" read a line up, up to timeout, return the remaining time """
	def readline(self, timeout):
		while True:
			n = self._buf.find("\n")
			if n >= 0:
				ret = self._buf[0:n]
				self._buf = self._buf[n + 1:]
				return ret, timeout

			if self._node.ssh:
				timeout = self.read_more_ssh(timeout)
			else:
				timeout = self.read_more_process(timeout)

			if timeout == 0:
				return "", 0

class CanDump(BackgroundProcess):
	def __init__(self, node):
		cmd = ["candump", "-e", node._can_if + ",0:0,#FFFFFFFF"]
		BackgroundProcess.__init__(self, node, cmd)

		timeout = 1000
		while node.run('pid=$(pgrep -n candump) && if [ -e /proc/$pid/fd/3 ]; then echo 1; else echo 0; fi', silent=True) != "1\n":
			time.sleep(0.050)
			timeout -= 50
			if timeout <= 0:
				raise TimeoutError

	def dump(self, silent = False):
		ret = BackgroundProcess.dump(self, True)
		if silent:
			return ret

		print("")
		print("## CANDUMP output ##")
		print(ret.rstrip("\n"))
		print("## END CANDUMP output ##")
		print("")

		return ret

class CanFdTest(BackgroundProcess):
	def __init__(self, node, cmd):
		BackgroundProcess.__init__(self, node, cmd)

		timeout = 1
		while node.run('pid=$(pgrep -n canfdtest) && if [ -e /proc/$pid/fd/3 ]; then echo 1; else echo 0; fi', silent=True) != "1\n":
			time.sleep(0.050)
			timeout -= 0.050
			if timeout <= 0:
				raise TimeoutError

	def dump(self, silent = False):
		ret = BackgroundProcess.dump(self, True).replace("N", "")
		if silent:
			return ret

		print(ret, end='', flush=True)

		return ret

class CanSeqeuence(BackgroundProcess):
	def __init__(self, node, receiver=True, count=None):
		# note: perhaps check with dlc 8 instead?
		# That causes less interrupts and is more in agreement with actual
		# payload. Since this passes as well for all interface it doesn't
		# really matter for now..
		cmd = ["cansequence", "-e", "-p", "-v"]
		if receiver:
			cmd.append("-r")
		if count:
			cmd.append("--loop=" + str(count))
		cmd.append(node._can_if)

		BackgroundProcess.__init__(self, node, cmd, get_pty=True)

class CanBusLoad(BackgroundProcess):
	def __init__(self, node):
		bitrate = node.get(["linkinfo", "info_data", "bittiming", "bitrate"])
		cmd = ["canbusload", "-e", node._can_if + "@" + str(bitrate)]
		BackgroundProcess.__init__(self, node, cmd)

class SocketcanTest:
	def __init__(self, dut, tester, acker, exit_on_error=False):
		self.exit_on_error = exit_on_error

		self.announce("INIT dut " + dut)
		hostname, can_if = self.get_hostinfo(dut)
		self._dut = SocketCanNode(can_if=can_if, role="dut", hostname=hostname)

		self.announce("INIT tester " + tester)
		hostname, can_if = self.get_hostinfo(tester)
		self._tester = SocketCanNode(can_if=can_if, role="tester", hostname=hostname)

		if acker:
			self.announce("INIT acker " + acker)
			hostname, can_if = self.get_hostinfo(acker)
			self._acker = SocketCanNode(can_if=can_if, role="acker", hostname=hostname)
		else:
			self._acker = None

	def run(self):
		self.check_send()
		self.check_send_when_down()
		self.check_bitrate_changes()
		self.check_tx_error_passive()
		self.check_bus_off()

		# The canfdtest is bidirectional and hence interesting since it causes lower
		# priority messages to be delayed, so the tx path should not be overwritten
		# or dropped. Since the program itself has delays, _don't_ run it it at a
		# too high bitrate, cansequence will be used for that.
		self.check_canfdtest(self._tester, self._dut, 125000)
		self.check_canfdtest(self._dut, self._tester, 125000)

		# No messages should be received out of order or dropped at 250kbit.
		self.check_cansequence(self._tester, self._dut, 250000)
		self.check_cansequence(self._dut, self._tester, 250000)

		# Not strictly needed, but keep this for now, since all interfaces pass it.
		self.check_cansequence(self._tester, self._dut, 500000)
		self.check_cansequence(self._dut, self._tester, 500000)

		self.start_test("DONE")

	def get_hostinfo(self, string):
		parts = string.split(":")
		if len(parts) == 1:
			return None, string

		return parts[0], parts[1]

	def eq(self, why, a, b):
		if a != b:
			print_err("!!! ERROR !!!: " + why + " " + str(a) + " != " + str(b))
			return

		print(" OK: " + why + " " + str(a) + " == " + str(b))

	def ge(self, why, a, b):
		if a < b:
			print_err("!!! ERROR !!!: " + why + " " + str(a) + " < " + str(b))
			return

		print(" OK: " + why + " " + str(a) + " >= " + str(b))

	def announce(self, text):
		print("")
		print(termcolor.colored("##### " + text + " #####", attrs=["bold"]))

	def start_test(self, descr):
		self.announce(descr)
		self._dut.if_down()
		self._tester.if_down()
		if self._acker:
			self._acker.if_down()

	""" Check if communication is possible or not, returns a boolean """
	def send_msg_and_rcv(self, src, target, dump=False):
		dumper = CanDump(target)
		src.send_msg()

		remaining = 1
		protocol_violation = False
		while True:
			msg, remaining = dumper.readline(timeout=remaining)

			if remaining == 0:
				dumper.close()
				return False, protocol_violation
			if dump:
				print(msg)
			if "protocol-violation" in msg:
				protocol_violation = True
			if msg.endswith("123   [8]  11 22 33 44 55 66 77 88"):
				dumper.close()
				return True, protocol_violation

	def send_msg_and_rcv_if(self, src, target, bitrate = 250000):
		src.if_up(bitrate=bitrate)
		target.if_up(bitrate=bitrate)

		ok1, violation1 = self.send_msg_and_rcv(src, target, dump=True)
		self.eq("sending a msg worked", ok1, True)

		ok2, violation2 = self.send_msg_and_rcv(target, src, dump=True)
		self.eq("receiving a msg worked", ok2, True)

		src.if_down()
		target.if_down()

		return ok1 and ok2, violation1 or violation2

	""" Check if a message can be send at all """
	def check_send(self):
		self.start_test("TESTING SEND")
		self.send_msg_and_rcv_if(self._dut, self._tester)

	def check_send_when_down(self):
		self.start_test("DOWN TEST")

		self._dut.if_up()
		self._dut.send_msg()
		self._dut.if_down()
		self._tester.if_up()

		self._tester.send_msg()
		state = self._tester.poll(["linkinfo", "info_data", "state"], "ERROR-PASSIVE")
		self.eq("when dut is down tester should become passive", state , "ERROR-PASSIVE")

	def check_bitrate_changes(self):
		self.start_test("BITRATE CHANGES")
		for _n in range(1, 3):
			_ok, violation = self.send_msg_and_rcv_if(self._dut, self._tester, bitrate=500000)
			self.eq("there should be no protocol violaton", violation, False)
			print("")
			_ok, violation = self.send_msg_and_rcv_if(self._dut, self._tester, bitrate=250000)
			self.eq("there should be no protocol violaton", violation, False)
			print("")


	""" Check if the device goes in error-passive and comes out of it again """
	def check_tx_error_passive(self):
		self.start_test("TESTING TX ERROR PASSIVE")

		self._dut.if_up(tx_queue_len=1000)

		# sniff around if it send events as well
		dumper = CanDump(self._dut)

		# initial state should be error-active / all fine
		state = self._dut.get(["linkinfo", "info_data", "state"])
		self._dut.eq("initial up state", state , "ERROR-ACTIVE")

		if self._dut.has_error_counters:
			self._dut.eq_p("initial up state, rec", ["linkinfo", "info_data", "berr_counter", "rx"], 0)
			self._dut.eq_p("initial up state, tec", ["linkinfo", "info_data", "berr_counter", "tx"], 0)

		# but it cannot send a message and should become error passive
		self._dut.send_msg()
		state = self._dut.poll(["linkinfo", "info_data", "state"], "ERROR-PASSIVE")
		self.eq("after no ack state", state , "ERROR-PASSIVE")

		if self._dut.has_error_counters:
			self._dut.eq_p("after no ack state, rec", ["linkinfo", "info_data", "berr_counter", "rx"], 0)
			tec = self._dut.ge_p("after no ack state, tec", ["linkinfo", "info_data", "berr_counter", "tx"], 128)
		else:
			# no error counters, sending 128 msgs should always get it error active again
			tec = 256

		# Since it cannot send, this dump should be little verbose, only
		# error messages... Remember if this sends a tx-error-warning if so
		# it is expected to go away as well., when it can send again.
		output = dumper.dump()
		warning_support = "controller-problem{tx-error-warning}" in output

		# how to check error passive?
		# sja1000 can detect those, but were to get the info from?

		# Now lets see if it returns to error-active
		self._tester.if_up()

		# now the still queued message should be send
		if self._dut.has_error_counters:
			expected_tec = tec - 1
			tec = self._dut.poll(["linkinfo", "info_data", "berr_counter", "tx"], expected_tec)
			self.eq("after tester is up, tec", tec, expected_tec)
		else:
			time.sleep(0.100)
			# transmission counters?

		output = dumper.dump()

		if warning_support:
			print(str(self._dut) + " has error-warning support")

			# Run till just before the end of error warning..
			n = int(tec) - 96
			self._dut.cangen(n)
			tec = self._dut.poll(["linkinfo", "info_data", "berr_counter", "tx"], 96)
			self.eq("to error-warning", tec , 96)

			# See https://github.com/torvalds/linux/commit/bac78aabcfece0c493b2ad824c68fbdc20448cbc,
			# added later on..
			output += dumper.dump(silent=True)
			did_notify = "controller-problem{tx-error-warning}" in output
			self.eq("should send tx-error-warning again", did_notify , True)

			# anyway, it should be in ERROR-WARNING again
			state = self._dut.poll(["linkinfo", "info_data", "state"], "ERROR-WARNING")
			self.eq("to error-warning", state , "ERROR-WARNING")

			output = dumper.dump(silent=True)
		else:
			# This is fine btw, as long as there is an error-passive state.
			print(str(self._dut) + " has no error-warning support or there is no notification")

		# Sending half of the tec frames back should make it error active again
		self._dut.cangen(int(tec / 2))
		state = self._dut.poll(["linkinfo", "info_data", "state"], "ERROR-ACTIVE")
		self.eq("error active again", state , "ERROR-ACTIVE")

		output = dumper.dump(silent=True)
		did_notify = "controller-problem{back-to-error-active}" in output
		self.eq("should send back-to-error-active", did_notify , True)

	def check_bus_off(self):
		self.start_test("TESTING BUS OFF")

		# Create stuff errors on the dut. The dut should no longer
		# active error when error-passive. The tester is allowed to
		# continue sending and can push the dut bus off.
		self._dut.if_up(bitrate=250000)
		self._tester.if_up(bitrate=125000)

		self._dut.send_stuff_msg()
		state = self._dut.poll(["linkinfo", "info_data", "state"], "BUS-OFF")
		self.eq("after pushing bus off", state , "BUS-OFF")

		# reset the tester, it also saw all kinds of bus errors, but that
		# was done on purpose...
		self._tester.if_down()

		time.sleep(0.5)
		state = self._dut.poll(["linkinfo", "info_data", "state"], "BUS-OFF")
		self.eq("should stick in bus off", state , "BUS-OFF")

		if self._acker:
			ok, violation = self.send_msg_and_rcv_if(self._tester, self._acker, bitrate=500000)
			self.eq("sending at a different bitrate should work when dut is bus-off", ok, True)
			self.eq("without violation", violation, False)

		self._tester.if_up(bitrate=125000)
		self._dut.if_down()
		self._dut.if_up(bitrate=125000)

		active, violation = self.send_msg_and_rcv(self._dut, self._tester, dump=True)
		self.eq("after down/up sending is possible again", active , True)
		self.eq("without violation", violation, False)

	def check_canfdtest(self, sender, replier, bitrate):
		self.start_test("CANFDTEST")

		replier.if_up(bitrate=bitrate)
		sender.if_up(bitrate=bitrate)

		on_acker = None
		if self._acker:
			self._acker.if_up(bitrate)
			on_acker = CanBusLoad(self._acker)

		on_replier = CanFdTest(replier, ["canfdtest", "-v", replier._can_if])
		on_sender = CanFdTest(sender, ["canfdtest", "-g", "-v", "-l", "10000", sender._can_if])

		result = ""
		load = ""
		print(replier._role + " " + str(replier) + ":")
		print("")
		print("===========================================")
		timeout = 30
		while on_sender.returncode() is None and timeout > 0:
			time.sleep(0.1)
			timeout -= 0.1
			result += on_sender.dump(silent=True)
			on_replier.dump()

			if on_acker:
				load += on_acker.dump(silent=True)

		on_sender.dump_cpuinfo_once()
		print("")

		if self._acker:
			load += on_acker.dump(silent=True)
			on_acker.close()
			on_acker.dump_cpuinfo_once()
			print("")

		on_replier.close()
		on_replier.dump_cpuinfo_once()

		print("")
		print(sender._role + " " + str(sender) + ":")
		print("===========================================")
		print(result)

		mismatch = "mismatch" in result
		sender.eq("canfdtest no mismatches", mismatch, False)
		sender.eq("no timeout", timeout > 0, True)
		sender.eq("canfdtest exit code should be zero", on_sender.returncode(), 0)

		if load:
			print("")
			print(self._acker._role + " " + str(self._acker) + ":")
			print("===========================================")
			print(load.replace("\n\n", "\n").strip("\n"))

	def check_cansequence(self, sender, receiver, bitrate):
		self.start_test("CANSEQUENCE")

		sender.if_up(bitrate, tx_queue_len=1000)
		receiver.if_up(bitrate)
		on_receiver = CanSeqeuence(receiver)

		on_acker = None
		if self._acker:
			self._acker.if_up(bitrate)
			on_acker = CanBusLoad(self._acker)

		on_sender = CanSeqeuence(sender, receiver=False, count=20000)

		print("")
		print("receiver: " + receiver._role + " " + str(receiver) + ":")
		print("===========================================")
		result = ""
		load = ""
		rx_output = ""
		timeout = 30
		while on_sender.returncode() is None and timeout > 0:
			time.sleep(0.1)
			timeout -= 0.1
			rx_output += on_receiver.dump()
			result += on_sender.dump(silent=True)

			if on_acker:
				load += on_acker.dump(silent=True)

		on_receiver.dump()
		on_receiver.dump_cpuinfo_once()
		print("")

		if self._acker:
			load += on_acker.dump(silent=True)
			on_acker.close()
			on_acker.dump_cpuinfo_once()
			print("")

		result += on_sender.dump(silent=True)
		on_sender.close()
		on_sender.dump_cpuinfo_once()
		print("")

		tx_msg = "sequence wrap around" in rx_output
		sender.eq("sender should have send msgs", tx_msg, True)
		rx_msg = "sequence wrap around" in rx_output
		receiver.eq("receiver should seen msg", rx_msg, True)
		wrong = "received wrong sequence count" in rx_output
		receiver.eq("should be no wrong seq", wrong, False)

		print("")
		print("sender: " + sender._role + " " + str(sender) + ":")
		print("===========================================")
		print(result)

		if load:
			print(self._acker._role + " " + str(self._acker) + ":")
			print("===========================================")
			print(load.replace("\n\n", "\n").strip("\n"))

def main(argv):
	global socketcanTest

	parser = argparse.ArgumentParser(
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description=textwrap.dedent('''
			Test if the Linux socketcan interface used in the Venus OS does what
			Venus OS expects it to do (and a bit more). The socketcan interfaces
			can be connected to the local machine or be controlled over ssh.
		'''),
		epilog=textwrap.dedent('''
			socketcan interface:
			  * can0, can1 etc to refer to the ones on the local machine.
			  * ccgx:can0 or 192.168.1.1:can1 for remote machines with root access.
			  * user@ccgx:can0 or user@192.168.1.1:can1 for other ssh users.

			Dependencies (on the target):
			  * This script relies on [1] and [2] being installed. The script doesn't
			    depend on Venus OS specifics, so it might be helpfull to test socketcan
			    drivers in general, but the requirements might differ.
			  * A recent version of iproute2 is need with json support.

			Venus OS requirements in short, the script itself should know the details..
			  * J1939 / NMEA 2000 / VE.Can @250000, full bus load, fifo, no msg lose.
			  * CAN-bus BMS @500000, little load, but might burst a bit. Since "a bit"
			    is rather hard to spec, stick to full bus load until it causes issues.
			  * Correct state reporting / bus error handling and recovery.
			  * Events of above, so userland is notified as well. (not a requirement at
			    the moment, but might become if that works reliably).
			  * Error counters are not needed, but since all our interfaces have them,
			    this script might depend on them.

			Notes:
			  * Do make sure the tester itself passes the test. At very least do a
			    proper reset on down / up, or the dut might get blamed for issues of
			    the tester. The (optional) acker is less important. Known to be good
				are in Venus after v2.40~32 are:
				  octo / venusgx - D_CAN (C_CAN is _not_ tested, no machine has one)
				  ccgx - ti_hecc
				  cerbo - sun4i_can
				  peakcan
				not passing:
				  kvaser leaf light
				  slcan (broken by design, can't even report its state)

			  * When using interfaces on the host, make sure this is done
			    sudo setcap cap_net_raw,cap_net_admin=eip /bin/ip
			    sudo setcap cap_net_raw,cap_net_admin=eip /sbin/tc

			Jeroen Hofsteee, Victron Energy B.V.

			[1] https://github.com/linux-can/can-utils
			[2] https://git.pengutronix.de/cgit/tools/canutils
			''')
		)
	parser.add_argument('-d', '--dut', help='socketcan interface to test')
	parser.add_argument('-e', '--exit-on-error', action='store_true', help='stop on the first error')
	parser.add_argument('-t', '--tester', help='socketcan interface which for testing')
	parser.add_argument('-a', '--acker', help='optional third socketcan interface to actual calculate busload / test bus-off etc')
	parser.add_argument('--forever', action='store_true', help='repeat the test endlessly')

	args = parser.parse_args(argv)

	if not isinstance(args.dut, str):
		print("error: dut must be a string")
		sys.exit(1)

	if not isinstance(args.tester, str):
		print("error: tester must be a string")
		sys.exit(1)

	print(termcolor.colored("##### Venus sockectcan test #####", attrs=["bold"]))

	try:
		while True:
			socketcanTest = SocketcanTest(args.dut, args.tester, args.acker, args.exit_on_error)
			socketcanTest.run()
			if not args.forever:
				break
	except Exception:
		traceback.print_exc(file=sys.stdout)
	finally:
		os._exit(1)

main(sys.argv[1:])
