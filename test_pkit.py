#!/usr/bin/env python3

# static bool arg_ask_password = true;
# static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
# polkit_agent_open_if_enabled(arg_transport, arg_ask_password);

# int polkit_agent_open_if_enabled(BusTransport transport, bool ask_password)
# if (transport != BUS_TRANSPORT_LOCAL)
#     return 0;
# if !ask_password
#    return 0;
# return polkit_agent_open();

# static pid_t agent_pid = 0;

# int polkit_agent_open(void) {
#         char notify_fd[DECIMAL_STR_MAX(int) + 1];
#         int pipe_fd[2], r;
# 
#         if (agent_pid > 0)
#                 return 0;
# 
#         /* Clients that run as root don't need to activate/query polkit */
#         if (geteuid() == 0)
#                 return 0;
# 
#         /* We check STDIN here, not STDOUT, since this is about input, not output */
#         if (!isatty(STDIN_FILENO))
#                 return 0;
# 
#         if (!is_main_thread())
#                 return -EPERM;
# 
#         if (pipe2(pipe_fd, 0) < 0)
#                 return -errno;
# 
#         xsprintf(notify_fd, "%i", pipe_fd[1]);
# 
#         r = fork_agent("(polkit-agent)",
#                        &pipe_fd[1], 1,
#                        &agent_pid,
#                        POLKIT_AGENT_BINARY_PATH,
#                        POLKIT_AGENT_BINARY_PATH, "--notify-fd", notify_fd, "--fallback", NULL);
# 
#         /* Close the writing side, because that's the one for the agent */
#         safe_close(pipe_fd[1]);
# 
#         if (r < 0)
#                 log_error_errno(r, "Failed to fork TTY ask password agent: %m");
#         else
#                 /* Wait until the agent closes the fd */
#                 fd_wait_for_event(pipe_fd[0], POLLHUP, USEC_INFINITY);
# 
#         safe_close(pipe_fd[0]);
# 
#         return r;
# }

# void polkit_agent_close(void) {
#
#        if (agent_pid <= 0)
#                return;
#
#         /* Inform agent that we are done */
#         (void) kill_and_sigcont(agent_pid, SIGTERM);
#         (void) wait_for_terminate(agent_pid, NULL);
#         agent_pid = 0;
# }

# int fork_agent(const char *name, const int except[], size_t n_except, pid_t *ret_pid, const char *path, ...) {
#        bool stdout_is_tty, stderr_is_tty;
#        size_t n, i;
#        va_list ap;
#        char **l;
#        int r;
#
#        assert(path);
#
#        /* Spawns a temporary TTY agent, making sure it goes away when we go away */
#
#        r = safe_fork_full(name, except, n_except, FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_CLOSE_ALL_FDS, ret_pid);
#        if (r < 0)
#                return r;
#        if (r > 0)
#                return 0;
#
#        /* In the child: */
#
#        stdout_is_tty = isatty(STDOUT_FILENO);
#        stderr_is_tty = isatty(STDERR_FILENO);
#
#        if (!stdout_is_tty || !stderr_is_tty) {
#                int fd;
#
#                 /* Detach from stdout/stderr. and reopen
#                  * /dev/tty for them. This is important to
#                  * ensure that when systemctl is started via
#                  * popen() or a similar call that expects to
#                  * read EOF we actually do generate EOF and
#                  * not delay this indefinitely by because we
#                  * keep an unused copy of stdin around. */
#                 fd = open("/dev/tty", O_WRONLY);
#                 if (fd < 0) {
#                         log_error_errno(errno, "Failed to open /dev/tty: %m");
#                         _exit(EXIT_FAILURE);
#                 }
#
#                 if (!stdout_is_tty && dup2(fd, STDOUT_FILENO) < 0) {
#                         log_error_errno(errno, "Failed to dup2 /dev/tty: %m");
#                         _exit(EXIT_FAILURE);
#                 }
#
#                 if (!stderr_is_tty && dup2(fd, STDERR_FILENO) < 0) {
#                         log_error_errno(errno, "Failed to dup2 /dev/tty: %m");
#                         _exit(EXIT_FAILURE);
#
#                         }
#
#                 safe_close_above_stdio(fd);
#         }
#
#         (void) rlimit_nofile_safe();
#
#         /* Count arguments */
#         va_start(ap, path);
#         for (n = 0; va_arg(ap, char*); n++)
#                ;
#         va_end(ap);
#
#         /* Allocate strv */
#         l = newa(char*, n + 1);
#
#         /* Fill in arguments */
#         va_start(ap, path);
#         for (i = 0; i <= n; i++)
#                 l[i] = va_arg(ap, char*);
#         va_end(ap);
#
#         execv(path, l);
#         _exit(EXIT_FAILURE);
# }

# (C) 2021 by Matteo Pasotti <matteo.pasotti@gmail.com>
# GPLv2

import select
import os
import pty
import dbus
import sys
from datetime import datetime


# https://vwangsf.medium.com/creating-a-d-bus-service-with-dbus-python-and-polkit-authentication-4acc9bc5ed29
def _check_polkit_privilege(self):
    # Get Peer PID
    if self.dbus_info is None:
        # Get DBus Interface and get info thru that
        self.dbus_info = dbus.Interface(conn.get_object("org.freedesktop.DBus",
                                                        "/org/freedesktop/DBus/Bus", False),
                                        "org.freedesktop.DBus")
    pid = self.dbus_info.GetConnectionUnixProcessID(sender)

    # Query polkit
    if self.polkit is None:
        self.polkit = dbus.Interface(dbus.SystemBus().get_object(
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority", False),
                                     "org.freedesktop.PolicyKit1.Authority")

    # Check auth against polkit; if it times out, try again
    try:
        auth_response = self.polkit.CheckAuthorization(
            ("unix-process", {"pid": dbus.UInt32(pid, variant_level=1),
                              "start-time": dbus.UInt64(0, variant_level=1)}),
            privilege, {"AllowUserInteraction": "true"}, dbus.UInt32(1), "", timeout=600)
        print(auth_response)
        (is_auth, _, details) = auth_response
    except dbus.DBusException as e:
        if e._dbus_error_name == "org.freedesktop.DBus.Error.ServiceUnknown":
            # polkitd timeout, retry
            self.polkit = None
            return self._check_polkit_privilege(sender, conn, privilege)
        else:
            # it's another error, propagate it
            raise

    if not is_auth:
        # Aww, not authorized :(
        print(":(")
        return False

    print("Successful authorization!")
    return True


def fd_wait_for_event(fd, event):
    poll = select.poll()
    poll.register(fd, select.POLLHUP) 
    fd_event = poll.poll()
    print("FD_EVENT: {}\n".format(fd_event[0]))
    print("POLLNVAL: {}\n".format(select.POLLNVAL))
    print("POLLHUP: {}\n".format(select.POLLHUP))
    if not fd_event:
        # empty list, no events to report and timeout reached
        return -1
    elif (fd_event[0][0] == 0):
        return 0

    if(fd_event[0][1] & select.POLLNVAL):
        print("POLLNVAL ERROR")
        return -hex(EBADF)
    # return the event
    return fd_event[0][1]
        
def polkit_agent_open():
    notify_fd = ""
    pipe_fd = os.pipe()

    print("PIPE: {}".format(pipe_fd))
    
    path = "/usr/bin/pkttyagent"

    notify_fd = "{}".format(pipe_fd[1])

    print("NOTIFY_FD: {}".format(notify_fd))

    (child_pid, child_fd) = fork_agent('(polkit-agent)', [path,'--notify-fd', notify_fd, '--fallback'])

    os.close(pipe_fd[1])

    if (child_pid < 0):
        print("Failed to fork TTY ask password agent")
    else:
        fd_wait_for_event(pipe_fd[0], select.POLLHUP);

    os.close(pipe_fd[0])

    return child_pid 



def fork_agent(name, path):
    os.path.isfile(path[0])
    print("path = {}".format(path[0]))

    (child_pid, child_fd) = pty.fork()

    print("ChildPID: {}".format(child_pid))

    if child_pid < 0:
        # error?
        return (child_pid, child_fd)
    if child_pid > 0:
        # parent process - return 0
        return (0, 0)

    # we're the child process :-)

    now = datetime.now()

    with open('child_output.log', 'a') as logger:
        logger.write("[{}] I'm the child process\n".format(now))

        try:
            stdout_is_tty = sys.stdout.isatty()
            stderr_is_tty = sys.stderr.isatty()
        except Exception as e:
            logger.write("[{}] {}\n".format(now, e))

        logger.write("[{}] STDOUT-IS-TTY: {}\n".format(now, stdout_is_tty))
        logger.write("[{}] STDERR-IS-TTY: {}\n".format(now, stderr_is_tty))

        if (not stdout_is_tty or not stderr_is_tty): 
            logger.write("[{}] condition not met".format(now))
        if (not stdout_is_tty or not stderr_is_tty): 
            fd = 0
            # Detach from stdout/stderr. and reopen
            # /dev/tty for them. This is important to
            # ensure that when systemctl is started via
            # popen() or a similar call that expects to
            # read EOF we actually do generate EOF and
            # not delay this indefinitely by because we
            # keep an unused copy of stdin around. */
            fd = open("/dev/tty", os.O_WRONLY)
            if (fd < 0):
                print("Failed to open /dev/tty: %m")
                exit(-14)
            if (not stdout_is_tty and os.dup2(fd, sys.stdout) < 0): 
                print("Failed to dup2 /dev/tty: %m")
                exit(-15)
            if (not stderr_is_tty and os.dup2(fd, sys.stderr) < 0):
                print("Failed to dup2 /dev/tty: %m")
                exit(-16)
            os.close(fd)

        logger.write("[{}] path before pop is\n\n{}\n\n".format(now, path))
        _path = path.pop(0)
        logger.write("[{}] Show _path {}\n".format(now, _path))
        os.execv(_path, path)
        exit(-20)



def test():

    bus = dbus.SystemBus()
    proxy = bus.get_object('org.freedesktop.hostname1', u'/org/freedesktop/hostname1')
    iface = dbus.Interface(proxy, dbus_interface='org.freedesktop.DBus.Properties')
    iface_set = dbus.Interface(proxy, dbus_interface='org.freedesktop.hostname1')
    #print (iface.GetAll('org.freedesktop.hostname1'))
    
    ret_val = polkit_agent_open()

    print("polkit_agent_open exit code: {}".format(ret_val))

    iface_set.SetHostname('vmga002', True)


test()

