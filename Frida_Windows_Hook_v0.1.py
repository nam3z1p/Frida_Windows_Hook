import frida
import sys


def on_message(message, data):
    print("[on_message] message:", message, "data:", data)


# full path of target binary
#path = "C:\\Target_Pull_Path"
#pid = frida.spawn(path)

pid = "notepad.exe"
session = frida.attach(pid)

script = session.create_script("""

//'target.exe' - name of exe
var baseAddr = Module.findBaseAddress('ntdll.dll');

//API offset(RVA)
//var offset = '0x1460';
//const hookAddr = baseAddr.add(offset);

//userFunc offset(RVA)
//userFuncAddr = baseAddr + offset

var target_library = "user32.dll"
var target_API = "SetWindowTextW"

const hookAddr = Module.findExportByName(target_library, target_API);

console.log('[*] '+target_library+' baseAddr : ' + baseAddr);
//console.log('[*] offset : ' + offset);
console.log('[*] '+target_API+' hookAddr : ' + hookAddr);

Interceptor.attach(hookAddr, {
        //Function is start
        onEnter: function (args) {
            console.log('##########################################################');
            console.log("[+] Send Called from:\\n" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\\n") + " ");
            console.log('##########################################################');
            console.log('[+] Called '+target_API+'!! [' + hookAddr + ']');
            console.log('[+] args[0] = [' + args[0] + ']');
            //DumpAddr('args[0]', args[0], 0x20);
            console.log('[+] args[1] = [' + args[1] + ']');
            DumpAddr('args[1]', args[1], 0x40);
            console.log('[+] args[2] = [' + args[2] + ']');
            //DumpAddr('args[2]', args[2], 0x30);
            //WriteMemory('args[2]', args[2], 0x120);
        },
        //Function is finished
        onLeave: function (retval) {
            console.log('##########################################################');
            console.log('[+] (Origin) typeof(retval) : ' + typeof(retval));
            console.log('[+] (Origin) retval : ' + retval);

            // Return retval change
            /*
            retval.replace(0);
            console.log('[+] (forgery) typeof(retval) : ' + typeof(retval));
            console.log('[+] (forgery) retval : ' + retval);
            */

            // return eax change */
            //this.context.eax = 0x0;

            console.log('Context information:');
            console.log('Context  : ' + JSON.stringify(this.context));
            console.log('ReturnAddr : ' + this.returnAddress);
            console.log('ThreadId : ' + this.threadId);
            console.log('Depth    : ' + this.depth);
            console.log('Errornr  : ' + this.err);
            console.log('##########################################################');
        }
    });

    //Print out data array
    function DumpAddr(info, addr, size) {
        if (addr.isNull())
            return;
        console.log('Data dump ' + info + ' :');
        var buf = Memory.readByteArray(addr, size);
        // If you want color magic, set ansi to true
        console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
    }

    //Write memory data
    function WriteMemory(info, addr, size) {
        if (addr.isNull())
            return;
        
        console.log('Write Memory ' + info + ' :');
        
        for (var i=0x00; i<size; i++){
            Memory.protect(addr.add(i), 0x01, "rwx");
            Memory.writeByteArray(addr.add(i), [0x65]);
            //point.push(addr.add(i));
            console.log(addr.add(i));
        }
    }

    function ResolveAddr(addr) {
        // Enter the base address of dll as seen in your favorite disassembler (here IDA)
        // Calculate offset in memory from base address in IDA database
        var idaBase = ptr('0x7FF60000');
        var offset = ptr(addr).sub(idaBase);
        var result = baseAddr.add(offset);
        console.log('[+] New addr=' + result);
        return result;
    }

""")
script.on("message", on_message)
script.load()
# frida.resume(pid)
print("[!] Ctrl+D on UNIX, Ctrl+C on Windows/cmd.exe \n    to detach from instrumented program.\n")
sys.stdin.read()
session.detach()
