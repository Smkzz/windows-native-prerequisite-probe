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
 static void EarlyRoot(string witness,string release) {
  string exe=System.Reflection.Assembly.GetExecutingAssembly().Location;
  Need(exe.IndexOf('"')<0);
  Startup si=new Startup();si.cb=(uint)Marshal.SizeOf(typeof(Startup));ProcessInfo pi;
  Need(CreateProcessW(exe,new StringBuilder("\""+exe+"\" leaf"),IntPtr.Zero,IntPtr.Zero,false,
       0x08000000|4,IntPtr.Zero,Path.GetDirectoryName(exe),ref si,out pi));
  try {
   Need(ResumeThread(pi.thread)!=0xffffffff);
   File.WriteAllText(witness,pi.pid.ToString());
   Stopwatch clock=Stopwatch.StartNew();
   while(!File.Exists(release)){Need(clock.ElapsedMilliseconds<8000);Thread.Sleep(10);}
  } finally { Need(CloseHandle(pi.thread));Need(CloseHandle(pi.process)); }
 }
 public static int Main(string[] args) {
  try {
   Need(args.Length>=1);
   if(args[0]=="stdio" && args.Length==1){Stdio();return 0;}
   if(args[0]=="early-root" && args.Length==3){EarlyRoot(args[1],args[2]);return 0;}
   if(args[0]=="leaf" && args.Length==1){Thread.Sleep(20000);return 0;}
   return 94;
  } catch { return 93; }
 }
}
