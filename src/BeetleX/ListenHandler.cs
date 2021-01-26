using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace BeetleX
{
    /// <summary>
    /// 监听处理类，负责tcp server监听，数字证书加载，客户端连接请求处理，并把接收到的客户端连接回调丢给外部tcpserver处理
    /// </summary>
    public class ListenHandler : IDisposable
    {
        /// <summary>
        /// 端口号
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// 监听地址host
        /// </summary>
        public string Host { get; set; }

        /// <summary>
        /// 数字证书的路径
        /// </summary>
        public string CertificateFile { get; set; }

        /// <summary>
        /// ssl协议，是否可以配置，不然客户端和服务端的ssl协议不一致很容易导致问题
        /// </summary>
        public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;

        /// <summary>
        /// 数字证书密码
        /// </summary>
        public string CertificatePassword { get; set; }

        /// <summary>
        /// 是否同步接收连接
        /// </summary>
        public bool SyncAccept { get; set; } = true;

        /// <summary>
        /// 是否是ssl
        /// </summary>
        public bool SSL { get; set; }

        /// <summary>
        /// 监听用的socket对象
        /// </summary>
        public Socket Socket { get; internal set; }

        /// <summary>
        /// 监听用的IP终结点信息
        /// </summary>
        public IPEndPoint IPEndPoint { get; private set; }

        /// <summary>
        /// 是否支持重用地址
        /// </summary>
        public bool ReuseAddress { get; set; } = false;

        /// <summary>
        /// tcp服务的操作对象，从外面传进来
        /// </summary>
        public IServer Server { get; internal set; }

        /// <summary>
        /// 数字证书对象
        /// </summary>
        public X509Certificate2 Certificate { get; internal set; }

        /// <summary>
        /// 接收连接请求的socket异步IO对象
        /// </summary>
        private SocketAsyncEventArgs mAcceptEventArgs = new SocketAsyncEventArgs();

        /// <summary>
        /// 连接回调，从tcp server传进来的连接回调处理函数，连接建立成功后socket异步IO事件会回调这个函数
        /// </summary>
        private Action<AcceptSocketInfo> mAcceptCallBack;

        /// <summary>
        /// 错误消息，当前监听处理类是否出现了异常
        /// </summary>
        public Exception Error { get; set; }

        /// <summary>
        /// 开始监听端口-加载ssl数字证书
        /// </summary>
        /// <param name="server">tcp服务对象</param>
        /// <param name="acceptCallback">tcp服务连接成功回调函数</param>
        internal void Run(IServer server, Action<AcceptSocketInfo> acceptCallback)
        {
            Server = server;
            mAcceptEventArgs.Completed += OnAcceptCompleted;
            mAcceptEventArgs.UserToken = this;
            mAcceptCallBack = acceptCallback;
            if (SSL)
            {
                //如果是ssl连接，创建数字证书
                if (string.IsNullOrEmpty(CertificateFile))
                {
                    if (server.EnableLog(EventArgs.LogType.Error))
                    {
                        server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} enabled ssl error certificate file name can not be null!");
                    }
                    return;
                }
                try
                {
                    Certificate = new X509Certificate2(CertificateFile, CertificatePassword);
                    if (server.EnableLog(EventArgs.LogType.Info))
                        server.Log(EventArgs.LogType.Info, null, $"load ssl certificate {Certificate}");
                }
                catch (Exception e_)
                {
                    Error = e_;
                    if (Server.EnableLog(EventArgs.LogType.Error))
                    {
                        Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} enabled ssl load certificate file error {e_.Message}|{e_.StackTrace}!");
                    }
                    return;
                }
            }
            //开始监听
            BeginListen();
        }

        /// <summary>
        /// 开始监听
        /// </summary>
        private void BeginListen()
        {
            try
            {
                System.Net.IPAddress address;
                //如果没有配置监听host
                if (string.IsNullOrEmpty(Host))
                {
                    //判断系统是否支持IPv6和当前是否配置使用IPv6
                    if (Socket.OSSupportsIPv6 && Server.Options.UseIPv6)
                    {
                        //使用ipv6任何地址
                        address = IPAddress.IPv6Any;
                    }
                    else
                    {
                        //监听ipv4任何地址
                        address = IPAddress.Any;
                    }
                }
                else
                {
                    //监听指定网卡当前地址
                    address = System.Net.IPAddress.Parse(Host);
                }
                IPEndPoint = new System.Net.IPEndPoint(address, Port);
                Socket = new Socket(IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                if (IPEndPoint.Address == IPAddress.IPv6Any)
                {
                    //如果ipv6任何地址，配置socket监听为双模式
                    //配置监听socket为 dual-mode (IPv4 & IPv6)
                    Socket.DualMode = true;
                }
                //如果是重用地址
                if (this.ReuseAddress)
                {
                    //配置socket底层配置为重用地址
                    Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                }
                //socket绑定ip终结点
                Socket.Bind(IPEndPoint);
                //开启监听
                //服务器未接手处理的连接最大数量512*4
                Socket.Listen(512 * 4);
                if (Server.EnableLog(EventArgs.LogType.Info))
                    Server.Log(EventArgs.LogType.Info, null, $"listen {Host}@{Port} success ssl:{SSL}");
                if (SyncAccept)
                {
                    //如果是同步连接
                    System.Threading.ThreadPool.QueueUserWorkItem((o) => OnSyncAccept());
                }
                else
                {
                    //如果是异步连接，使用异步IO对象去接收连接
                    OnAsyncAccept();
                }
            }
            catch (Exception e_)
            {
                Error = e_;
                if (Server.EnableLog(EventArgs.LogType.Error))
                {
                    Server.Log(EventArgs.LogType.Error, null, $"listen {Host}@{Port} error {e_.Message}|{e_.StackTrace}!");
                }
            }
        }

        /// <summary>
        /// 建立连接失败超过一定次数会停止建立连接
        /// </summary>
        private int mAccetpError = 0;

        /// <summary>
        /// 开启监听后调这个方法
        /// 当前方法是同步接收客户端连接，用的不是异步IO对象，这个性能稍差。
        /// </summary>
        private void OnSyncAccept()
        {
            //同步接收连接请求
            while (true)
            {
                try
                {
                    while (Server.Status == ServerStatus.Stop)
                        System.Threading.Thread.Sleep(500);
                    //如果没有连接进来，会阻塞在这个Accept方法，直到有一个连接进来会继续往下走。
                    var acceptSocket = Socket.Accept();
                    //包装socket对象信息
                    AcceptSocketInfo item = new AcceptSocketInfo();
                    //把socket对象放进包装对象
                    item.Socket = acceptSocket;
                    //赋值监听器为当前类
                    item.Listen = this;
                    //回调tcp服务的连接成功处理回调
                    mAcceptCallBack(item);
                }
                catch (Exception e_)
                {
                    Error = e_;
                    //连接错误计数
                    mAccetpError++;
                    if (Server.EnableLog(EventArgs.LogType.Error))
                    {
                        Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} accept error {e_.Message}|{e_.StackTrace}!");
                    }
                    if (mAccetpError >= 10)
                    {
                        //连接错误计数>=10，当前server状态为error将不会再继续接收新的连接
                        if (Server.EnableLog(EventArgs.LogType.Warring))
                        {
                            Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} accept stoped!");
                        }
                        Server.Status = ServerStatus.Error;
                        //弹出
                        break;
                    }
                }
            }
        }

        /// <summary>
        /// 异步io建立连接回调
        /// 当前有客户端连接过来，异步IO对象会自动触发这个事件，通知我们的服务端应用去处理连接
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void OnAcceptCompleted(object sender, SocketAsyncEventArgs e)
        {
            try
            {
                //如果连接成功
                if (e.SocketError == SocketError.Success)
                {
                    //打印远程客户端的信息
                    if (Server.EnableLog(EventArgs.LogType.Debug))
                    {
                        Server.Log(EventArgs.LogType.Debug, null, $"{Host}@{Port} accept success from {e.AcceptSocket.RemoteEndPoint}");
                    }
                    //包装客户端的socket对象
                    AcceptSocketInfo item = new AcceptSocketInfo();
                    //把异步IO拿到的连接socket对象，赋值给当前包装对象
                    item.Socket = e.AcceptSocket;
                    //赋值监听处理器
                    item.Listen = this;
                    //清除socket异步io对象里的socket连接对象，清除之后下次给其他连接用
                    e.AcceptSocket = null;
                    //回调tcpserver连接成功处理函数，外面的tcp服务还需要一些特殊操作，比如添加session会话对象
                    mAcceptCallBack(item);
                    //连接失败错误计数清零
                    mAccetpError = 0;
                }
                else
                {
                    if (Server.EnableLog(EventArgs.LogType.Error))
                    {
                        Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} accept completed socket error {e.SocketError}!");
                    }
                }
            }
            catch (Exception e_)
            {
                if (Server.EnableLog(EventArgs.LogType.Error))
                {
                    Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} accept completed error {e_.Message}|{e_.StackTrace}!");
                }
            }
            finally
            {
                if (mAsyncAccepts >= 50)
                {
                    mAsyncAccepts = 0;
                    Task.Run(() => { OnAsyncAccept(); });
                }
                else
                {
                    OnAsyncAccept();
                }
            }
        }

        private int mAsyncAccepts = 0;

        /// <summary>
        /// 开启监听后调这个方法
        /// 开始异步连接处理方法
        /// 连接完成回调方法执行完了之后还会回来调这个方法，继续接收下一个连接，
        /// 如果有连接进来，异步IO的事件会自动触发
        /// </summary>
        private void OnAsyncAccept()
        {
        START_ACCEPT:
            if (Server.EnableLog(EventArgs.LogType.Debug))
            {
                Server.Log(EventArgs.LogType.Debug, null, $"{Host}@{Port} begin accept");
            }
            try
            {
                while (Server.Status == ServerStatus.Stop)
                    System.Threading.Thread.Sleep(500);
                //清空上次连接成功的socket客户端对象
                mAcceptEventArgs.AcceptSocket = null;
                //AcceptAsync=true，说明操作是异步完成的，如果=false，说明立即可用，同步接受的连接
                if (!Socket.AcceptAsync(mAcceptEventArgs))
                {
                    //如果socket连接已经完成了
                    //这个方法一直都是同步执行的所以这个值可以++不需要原子操作
                    //正常情况下不会=false，所以这边一直++如果超过50就使用task去启动当前方法
                    mAsyncAccepts++;
                    //手动触发连接完成回调
                    OnAcceptCompleted(this, mAcceptEventArgs);
                }
                else
                {
                    mAsyncAccepts = 0;
                }
                //清空连接失败计数
                mAccetpError = 0;
            }
            catch (Exception e_)
            {
                Error = e_;
                //连接失败计数+1
                mAccetpError++;
                if (Server.EnableLog(EventArgs.LogType.Error))
                {
                    Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} accept error {e_.Message}|{e_.StackTrace}!");
                }
                if (mAccetpError >= 10)
                {
                    //当前连接失败计数>=10，当前server将不再接收新的tcp连接
                    if (Server.EnableLog(EventArgs.LogType.Warring))
                    {
                        Server.Log(EventArgs.LogType.Error, null, $"{Host}@{Port} accept stoped!");
                    }
                    Server.Status = ServerStatus.Error;
                }
                else
                    //如果连接错误计数没有超过10则将继续接收客户端连接请求
                    goto START_ACCEPT;
            }
        }

        /// <summary>
        /// 打印当前类的信息
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return $"Listen {Host}:{Port}\t[SSL:{SSL}]\t[Status:{(Error == null ? "success" : $"error {Error.Message}")}]";
        }

        /// <summary>
        /// 释放socket监听器
        /// </summary>
        public void Dispose()
        {
            try
            {
                TcpServer.CloseSocket(Socket);
            }
            catch
            {

            }
        }
    }

    /// <summary>
    /// socket连接信息包装类
    /// </summary>
    class AcceptSocketInfo
    {
        /// <summary>
        /// 监听处理器
        /// </summary>
        public ListenHandler Listen { get; set; }
        /// <summary>
        /// 客户端socket对象
        /// </summary>
        public Socket Socket { get; set; }
    }
}
