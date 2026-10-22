using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using System.Diagnostics;
public static class LimitedIoProbe {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
 struct Startup {
  public uint cb; public string reserved,desktop,title;
  public uint x,y,xsize,ysize,xchars,ychars,fill,flags;
  public ushort show,reserved2; public IntPtr reservedPtr,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)]
 struct ProcessInfo { public IntPtr process,thread; public uint pid,tid; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode,SetLastError=true)]
 static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,
  uint flags,IntPtr environment,string cwd,ref Startup startup,out ProcessInfo process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr handle,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 static void Need(bool ok) { if(!ok) throw new InvalidOperationException("FIXED_HELPER_REQUIREMENT"); }
 static void Stdio() {
  byte[] expected=Encoding.ASCII.GetBytes("LOCALCONTROL_STDIO_V1\n"+new string('a',128));
  byte[] data=new byte[expected.Length+1];
  Stream input=Console.OpenStandardInput();int count=0,n;
  while((n=input.Read(data,count,data.Length-count))>0) { count+=n;Need(count<data.Length); }
  Need(count==expected.Length);
  for(int i=0;i<count;i++)Need(data[i]==expected[i]);
  byte[] output=Encoding.ASCII.GetBytes(new string('O',32768));
  byte[] error=Encoding.ASCII.GetBytes(new string('E',32768));
  Stream stdout=Console.OpenStandardOutput(),stderr=Console.OpenStandardError();
  for(int i=0;i<3;i++){stdout.Write(output,0,output.Length);stdout.Flush();stderr.Write(error,0,error.Length);stderr.Flush();}
 }
 static void Chain(int depth,string output) {
  Need(depth>=1 && depth<=3 && Directory.Exists(output));
  File.WriteAllText(Path.Combine(output,"chain-"+depth.ToString()+".pid"),Process.GetCurrentProcess().Id.ToString());
  if(depth>1) {
   string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;
   Need(exe.IndexOf('"')<0 && output.IndexOf('"')<0);
   Startup si=new Startup();si.cb=(uint)Marshal.SizeOf(typeof(Startup));ProcessInfo pi;
   Need(CreateProcessW(exe,new StringBuilder("\""+exe+"\" chain "+(depth-1).ToString()+" \""+output+"\""),IntPtr.Zero,IntPtr.Zero,false,
        0x08000000|4,IntPtr.Zero,Path.GetDirectoryName(exe),ref si,out pi));
   bool failed=false;
   try { failed=ResumeThread(pi.thread)==0xffffffff; }
   catch { failed=true; }
   // An unsuccessful release or thread close must stop this exact owned child.
   bool threadClosed=CloseHandle(pi.thread);
   if(!threadClosed)failed=true;
   bool stopped=true;
   if(failed) { TerminateProcess(pi.process,125); stopped=WaitForSingleObject(pi.process,2000)==0; }
   bool processClosed=CloseHandle(pi.process);
   if(!processClosed) {
    // Failed close leaves the exact handle retained, never a PID-based target.
    TerminateProcess(pi.process,125);
    bool exited=WaitForSingleObject(pi.process,2000)==0;
    bool retryClosed=CloseHandle(pi.process);
    failed=true;
    if(!exited || !retryClosed)failed=true;
   }
   if(!threadClosed) { CloseHandle(pi.thread); failed=true; }
   Need(!failed && stopped && processClosed);
  }
  Thread.Sleep(20000);
 }
 public static int Main(string[] args) {
  try {
   Need(args.Length>=1);
   if(args[0]=="chain" && args.Length==3){Chain(Int32.Parse(args[1]),args[2]);return 0;}
   if(args[0]=="stdio" && args.Length==1){Stdio();return 0;}
   if(args[0]=="leaf" && args.Length==1){Thread.Sleep(20000);return 0;}
   return 94;
  } catch { return 93; }
 }
}
