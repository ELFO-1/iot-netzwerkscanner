#!/usr/bin/env python3
"""
Metasploit RPC Client for Python

This module provides a simple interface to the Metasploit RPC server.
"""

import http.client
import json
import ssl
import base64
import time

class Msfrpc:
    """A thin wrapper for Metasploit RPC"""
    
    def __init__(self, opts=None):
        """Initialize the Msfrpc object
        
        Args:
            opts (dict): Options for the RPC connection
                - host (str): The host to connect to (default: 127.0.0.1)
                - port (int): The port to connect to (default: 55553)
                - uri (str): The URI to connect to (default: /api/)
                - ssl (bool): Whether to use SSL (default: True)
                - verify_ssl (bool): Whether to verify SSL certificates (default: False)
                - timeout (int): Connection timeout in seconds (default: 30)
        """
        self.host = '127.0.0.1'
        self.port = 55553
        self.uri = '/api/'
        self.use_ssl = True
        self.verify_ssl = False
        self.timeout = 30
        self.token = None
        self.headers = {'Content-Type': 'application/json'}
        
        if opts is not None:
            self.host = opts.get('host', self.host)
            self.port = opts.get('port', self.port)
            self.uri = opts.get('uri', self.uri)
            self.use_ssl = opts.get('ssl', self.use_ssl)
            self.verify_ssl = opts.get('verify_ssl', self.verify_ssl)
            self.timeout = opts.get('timeout', self.timeout)
    
    def _connect(self):
        """Connect to the RPC server
        
        Returns:
            http.client.HTTPConnection or http.client.HTTPSConnection: The connection object
        """
        if self.use_ssl:
            context = ssl.create_default_context()
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(self.host, self.port, context=context, timeout=self.timeout)
        else:
            return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
    
    def call(self, method, opts=None):
        """Call a method on the RPC server
        
        Args:
            method (str): The method to call
            opts (dict): Options for the method
        
        Returns:
            dict: The response from the server
        """
        if opts is None:
            opts = {}
        
        if self.token is not None and method != 'auth.login':
            opts['token'] = self.token
        
        params = {
            'method': method,
            'params': opts
        }
        
        conn = self._connect()
        try:
            conn.request('POST', self.uri, json.dumps(params), self.headers)
            response = conn.getresponse()
            data = response.read().decode('utf-8')
            if response.status != 200:
                raise Exception(f"Error: {response.status} {response.reason}\n{data}")
            return json.loads(data)
        finally:
            conn.close()
    
    def login(self, username, password):
        """Login to the RPC server
        
        Args:
            username (str): The username to login with
            password (str): The password to login with
        
        Returns:
            dict: The response from the server
        """
        result = self.call('auth.login', {'username': username, 'password': password})
        if result.get('result') == 'success':
            self.token = result.get('token')
        return result
    
    def logout(self):
        """Logout from the RPC server
        
        Returns:
            dict: The response from the server
        """
        result = self.call('auth.logout', {})
        self.token = None
        return result
    
    def console_create(self):
        """Create a new console
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.create')
    
    def console_destroy(self, console_id):
        """Destroy a console
        
        Args:
            console_id (str): The ID of the console to destroy
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.destroy', {'id': console_id})
    
    def console_write(self, console_id, command):
        """Write to a console
        
        Args:
            console_id (str): The ID of the console to write to
            command (str): The command to write
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.write', {'id': console_id, 'command': command + '\n'})
    
    def console_read(self, console_id):
        """Read from a console
        
        Args:
            console_id (str): The ID of the console to read from
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.read', {'id': console_id})
    
    def console_list(self):
        """List all consoles
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.list')
    
    def console_session_kill(self, session_id):
        """Kill a console session
        
        Args:
            session_id (str): The ID of the session to kill
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.session_kill', {'id': session_id})
    
    def console_tabs(self, console_id, line):
        """Get tab completion for a line
        
        Args:
            console_id (str): The ID of the console
            line (str): The line to complete
        
        Returns:
            dict: The response from the server
        """
        return self.call('console.tabs', {'id': console_id, 'line': line})
    
    def module_list(self, module_type=None):
        """List all modules
        
        Args:
            module_type (str, optional): The type of module to list
        
        Returns:
            dict: The response from the server
        """
        if module_type:
            return self.call('module.list', {'type': module_type})
        return self.call('module.list')
    
    def module_info(self, module_type, module_name):
        """Get information about a module
        
        Args:
            module_type (str): The type of module
            module_name (str): The name of the module
        
        Returns:
            dict: The response from the server
        """
        return self.call('module.info', {'type': module_type, 'name': module_name})
    
    def module_options(self, module_type, module_name):
        """Get options for a module
        
        Args:
            module_type (str): The type of module
            module_name (str): The name of the module
        
        Returns:
            dict: The response from the server
        """
        return self.call('module.options', {'type': module_type, 'name': module_name})
    
    def module_execute(self, module_type, module_name, options=None):
        """Execute a module
        
        Args:
            module_type (str): The type of module
            module_name (str): The name of the module
            options (dict, optional): Options for the module
        
        Returns:
            dict: The response from the server
        """
        if options is None:
            options = {}
        return self.call('module.execute', {'type': module_type, 'name': module_name, 'options': options})
    
    def job_list(self):
        """List all jobs
        
        Returns:
            dict: The response from the server
        """
        return self.call('job.list')
    
    def job_stop(self, job_id):
        """Stop a job
        
        Args:
            job_id (str): The ID of the job to stop
        
        Returns:
            dict: The response from the server
        """
        return self.call('job.stop', {'id': job_id})
    
    def job_info(self, job_id):
        """Get information about a job
        
        Args:
            job_id (str): The ID of the job
        
        Returns:
            dict: The response from the server
        """
        return self.call('job.info', {'id': job_id})
    
    def session_list(self):
        """List all sessions
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.list')
    
    def session_stop(self, session_id):
        """Stop a session
        
        Args:
            session_id (str): The ID of the session to stop
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.stop', {'id': session_id})
    
    def session_shell_read(self, session_id):
        """Read from a shell session
        
        Args:
            session_id (str): The ID of the session to read from
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.shell_read', {'id': session_id})
    
    def session_shell_write(self, session_id, command):
        """Write to a shell session
        
        Args:
            session_id (str): The ID of the session to write to
            command (str): The command to write
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.shell_write', {'id': session_id, 'data': command + '\n'})
    
    def session_meterpreter_read(self, session_id):
        """Read from a meterpreter session
        
        Args:
            session_id (str): The ID of the session to read from
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.meterpreter_read', {'id': session_id})
    
    def session_meterpreter_write(self, session_id, command):
        """Write to a meterpreter session
        
        Args:
            session_id (str): The ID of the session to write to
            command (str): The command to write
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.meterpreter_write', {'id': session_id, 'data': command + '\n'})
    
    def session_meterpreter_run_single(self, session_id, command):
        """Run a single command in a meterpreter session
        
        Args:
            session_id (str): The ID of the session
            command (str): The command to run
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.meterpreter_run_single', {'id': session_id, 'command': command})
    
    def session_meterpreter_script(self, session_id, script):
        """Run a script in a meterpreter session
        
        Args:
            session_id (str): The ID of the session
            script (str): The script to run
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.meterpreter_script', {'id': session_id, 'script': script})
    
    def session_meterpreter_session_detach(self, session_id):
        """Detach from a meterpreter session
        
        Args:
            session_id (str): The ID of the session to detach from
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.meterpreter_session_detach', {'id': session_id})
    
    def session_meterpreter_session_kill(self, session_id):
        """Kill a meterpreter session
        
        Args:
            session_id (str): The ID of the session to kill
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.meterpreter_session_kill', {'id': session_id})
    
    def session_compatible_modules(self, session_id):
        """Get compatible modules for a session
        
        Args:
            session_id (str): The ID of the session
        
        Returns:
            dict: The response from the server
        """
        return self.call('session.compatible_modules', {'id': session_id})

# Example usage
def main():
    """Example usage of the Msfrpc class"""
    client = Msfrpc({'host': '127.0.0.1', 'port': 55553})
    auth = client.login('msf', 'msf')
    
    if auth.get('result') == 'success':
        print("Authentication successful")
        
        # Create a console
        console = client.console_create()
        console_id = console.get('id')
        
        # Write a command to the console
        client.console_write(console_id, 'version')
        
        # Wait for the command to complete
        time.sleep(1)
        
        # Read the output
        output = client.console_read(console_id)
        print(output.get('data'))
        
        # Destroy the console
        client.console_destroy(console_id)
        
        # Logout
        client.logout()
    else:
        print("Authentication failed")

if __name__ == "__main__":
    main()