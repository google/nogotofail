/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.nogotofail;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * Daemon that, when running, maintains a connection to the MiTM server. The traffic over the
 * connection is handled by a {@link ConnectionHandler} provided to the daemon.
 *
 * <p>The daemon reports its state changes to {@link StateChangeListener} instances registered using
 * {@link #addStateChangeListener(StateChangeListener) addStateChangeListener}.
 */
public class RouterSocketClient {

  /**
   * Handler of the traffic over the connection to a MiTM server. Once the handler is done with a
   * connection, the connection is closed.
   */
  public interface ConnectionHandler {
    void handleConnection(Socket socket) throws IOException;
  }

  /**
   * Receiver of state change events.
   */
  public interface StateChangeListener {
    void onStarted();
    void onConnecting(InetSocketAddress address);
    void onConnected(InetSocketAddress address);
    void onWaitingToRetry(String cause, long delayMillis);
    void onStopped();
    void onUnknownCertificate(X509Certificate certificate);
  }

  private static final String TAG = RouterSocketClient.class.getSimpleName();
  private static final long MIN_DELAY_MILLIS = TimeUnit.SECONDS.toMillis(2);
  private static final long MAX_DELAY_MILLIS = TimeUnit.MINUTES.toMillis(30);

  private static final int SERVER_CONNECT_TIMEOUT_MILLIS = 20000;
  private static final int HTTP_PROXY_CONNECT_TIMEOUT_MILLIS = 5000;
  private static final int TLS_HANDSHAKE_TIMEOUT_MILLIS = 20000;

  private static enum ConnectionState {
    DISCONNECTED,
    STARTING,
    RUNNING,
    STOPPING,
    STOPPING_RESTART_REQUESTED,
  }


  private final Object mLock = new Object();
  private final ConnectionHandler mConnectionHandler;
  private final ConnectivityManager mConnectivityManager;
  private final Random mRng;
  private final SSLSocketFactory mSSLSocketFactory;

  private enum StateChangeEventType {
    STARTED,
    CONNECTING,
    CONNECTED,
    WAITING_TO_RETRY,
    STOPPED,
    UNKNOWN_CERTIFICATE,
  }
  private static class StateChangeEvent {
    private final StateChangeEventType mType;
    private final InetSocketAddress mAddress;
    private final String mCause;
    private final long mDelayMillis;
    private final X509Certificate mCertificate;

    private StateChangeEvent(StateChangeEventType type) {
      mType = type;
      mAddress = null;
      mCause = null;
      mDelayMillis = 0;
      mCertificate = null;
    }

    private StateChangeEvent(StateChangeEventType type, InetSocketAddress address) {
      mType = type;
      mAddress = address;
      mCause = null;
      mDelayMillis = 0;
      mCertificate = null;
    }

    private StateChangeEvent(StateChangeEventType type, String cause, long delayMillis) {
      mType = type;
      mAddress = null;
      mCause = cause;
      mDelayMillis = delayMillis;
      mCertificate = null;
    }

    private StateChangeEvent(StateChangeEventType type, X509Certificate certificate) {
      mType = type;
      mAddress = null;
      mCause = null;
      mDelayMillis = 0;
      mCertificate = certificate;
    }
  }

  /** @GuardedBy {@link #mLock} */
  private StateChangeEvent mLastStateChangeEvent =
      new StateChangeEvent(StateChangeEventType.STOPPED);
  private final CopyOnWriteArrayList<StateChangeListener> mStateChangeListeners =
      new CopyOnWriteArrayList<StateChangeListener>();

  private final Context mContext;
  private final Handler mDelayedRestartHandler;
  private final PreferencesBackedPinningX509TrustManager mTrustManager;

  /**
   * Listener invoked whenever preferences change.
   *
   * <p><em>NOTE:</em> {@code SharedPreferences} uses a {@code WeakHashMap} to store its listeners.
   * Thus, listeners may be garbage-collected unless they are hard-referenced from elsewhere.
   * Referencing the listener from a final field of this instance creates a hard-reference for the
   * whole lifetime of this instance.  */
  private final SharedPreferences.OnSharedPreferenceChangeListener mPreferencesChangeListener;

  /** @GuardedBy {@link #mLock} */
  private ConnectionState mConnectionState = ConnectionState.DISCONNECTED;
  /** @GuardedBy {@link #mLock} */
  private Thread mThread;
  /** @GuardedBy {@link #mLock} */
  private Socket mSocket;
  /** @GuardedBy {@link #mLock} */
  private long mNextDelayMillis = 0;

  /** @GuardedBy {@link #mLock} */
  private Runnable mDelayedRestartRunnable;

  public RouterSocketClient(
      Context context,
      ConnectivityManager connectivityManager,
      ConnectionHandler connectionHandler,
      Random rng) {
    mContext = context;
    mDelayedRestartHandler = new Handler(mContext.getMainLooper());
    mConnectivityManager = connectivityManager;
    mConnectionHandler = connectionHandler;
    mRng = rng;
    mTrustManager = new PreferencesBackedPinningX509TrustManager(mContext);
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(
          new KeyManager[0], // No need for client or server keys
          new TrustManager[] {
            mTrustManager
          },
          null // use default RNG source
          );
      mSSLSocketFactory = sslContext.getSocketFactory();
    } catch (Exception e) {
      throw new RuntimeException("Failed to initialize SSLSocketFactory", e);
    }

    // Listen for changes in SharedPreferences that may require reconnecting
    mPreferencesChangeListener = new SharedPreferences.OnSharedPreferenceChangeListener() {
      @Override
      public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
        Log.d(TAG, "onSharedPreferenceChanged(\"" + key + "\")");
        if ((AttacksPreferenceFragment.isReconnectRequiredToApplyPreference(mContext, key))
            || (AdvancedPreferenceFragment.isReconnectRequiredToApplyPreference(mContext, key))) {
          // Multiple settings may change roughly at the same time. To avoid restarting multiple
          // times in quick succession, we schedule delayed restarts. Because of the way the
          // scheduling method below works, this results in only one restart request albeit with
          // after a delay.
          scheduleDelayedRestart("Setting changed: " + key);
        }
      }
    };
    SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(context);
    sharedPreferences.registerOnSharedPreferenceChangeListener(mPreferencesChangeListener);
  }

  /**
   * Registers the provided listener and immediately notifies it about the most recent event
   * (if any).
   */
  public void addStateChangeListener(StateChangeListener listener) {
    StateChangeEvent lastEvent;
    synchronized (mLock) {
      lastEvent = mLastStateChangeEvent;
    }
    if (lastEvent != null) {
      notifyEvent(listener, lastEvent);
    }
    mStateChangeListeners.add(listener);
  }

  public void removeStateChangeListener(StateChangeListener listener) {
    mStateChangeListeners.remove(listener);
  }

  /**
   * Invoked when the data connectivity state may have changed.
   *
   * @param activeNetworkInfo information about the active data network, or {@code null} if no
   *        data network is available.
   */
  void onDataConnectivityMayHaveChanged(NetworkInfo activeNetworkInfo) {
    if (activeNetworkInfo == null) {
      Log.i(TAG, "No data connectivity");
    } else {
      Log.i(TAG, "Data connectivity may have changed."
          + " Active network type: " + activeNetworkInfo.getTypeName()
          + ", subtype: " + activeNetworkInfo.getSubtypeName()
          + ", state: " + activeNetworkInfo.getState());
    }
    if ((activeNetworkInfo != null) && (activeNetworkInfo.isConnected())) {
      resetRetryState();
      start();
    } else {
      stop();
    }
  }

  public void onServiceStarted() {
    Log.i(TAG, "onServiceStarted()");
    resetRetryState();
    start();
  }

  public void onServiceStopped() {
    Log.i(TAG, "onServiceStopped");
    stop();
  }

  private void setConnectionState(ConnectionState state) {
    synchronized (mLock) {
      if (mConnectionState != state) {
        Log.d(TAG, mConnectionState + " -> " + state);
        mConnectionState = state;
      }
    }
  }

  /**
   * Schedules a delayed restart request. If the method is invoked multiple times in succession,
   * only the most recent request is honored.
   */
  private void scheduleDelayedRestart(String reason) {
    Log.d(TAG, "Scheduling a delayed restart. Reason: " + reason);
    Runnable runnable = new Runnable() {
      @Override
      public void run() {
        synchronized (mLock) {
          if (mDelayedRestartRunnable != this) {
            // Another Runnable replaced this one
            return;
          }
          mDelayedRestartRunnable = null;
        }
        restart();
      }
    };
    synchronized (mLock) {
      if (mDelayedRestartRunnable != null) {
        mDelayedRestartHandler.removeCallbacks(mDelayedRestartRunnable);
      }
      mDelayedRestartRunnable = runnable;
      mDelayedRestartHandler.postDelayed(runnable, 1000);
    }
  }

  public void restart() {
    Log.d(TAG, "restart()");
    stop();
    resetRetryState();
    start();
  }

  public void start() {
    Log.d(TAG, "start()");
    synchronized (mLock) {
      switch (mConnectionState) {
        case DISCONNECTED:
          setConnectionState(ConnectionState.STARTING);
          Log.i(TAG, "Starting...");
          Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
              blockingRun();
            }
          });
          mThread = thread;
          thread.start();
          break;
        case STARTING:
        case RUNNING:
          break;
        case STOPPING:
        case STOPPING_RESTART_REQUESTED:
          setConnectionState(ConnectionState.STOPPING_RESTART_REQUESTED);
          break;
        default:
          throw new IllegalStateException(String.valueOf(mConnectionState));
      }
    }
  }

  public void stop() {
    Log.d(TAG, "stop()");

    final Socket socket;
    Thread thread;
    synchronized (mLock) {
      switch (mConnectionState) {
        case STARTING:
        case RUNNING:
        case STOPPING:
        case STOPPING_RESTART_REQUESTED:
          setConnectionState(ConnectionState.STOPPING);
          break;
        case DISCONNECTED:
          return;
        default:
          throw new IllegalStateException(String.valueOf(mConnectionState));
      }

      socket = mSocket;
      mSocket = null;
      thread = mThread;
      mThread = null;
    }

    if (socket != null) {
      new Thread(new Runnable() {
        @Override
        public void run() {
          Closeables.closeQuietly(socket);
        }
      }).start();
    }
    if (thread != null) {
      Log.d(TAG, "Interrupting background thread...");
      thread.interrupt();
    }
  }

  public void close() {
    Log.d(TAG, "close()");
    stop();
  }

  private void blockingRun() {
    Log.i(TAG, "Running");

    notifyStarted();
    try {
      while (true) {
        switch (mConnectionState) {
          case STARTING:
          case RUNNING:
            setConnectionState(ConnectionState.RUNNING);
            break;
          case STOPPING:
          case STOPPING_RESTART_REQUESTED:
          case DISCONNECTED:
            return;
          default:
            throw new IllegalStateException(String.valueOf(mConnectionState));
        }

        NetworkInfo networkInfo = mConnectivityManager.getActiveNetworkInfo();
        if ((networkInfo == null) || (!networkInfo.isConnected())) {
          Log.w(TAG, "No data connectivity. Stopping");
          return;
        }

        Socket socket = null;
        try {
          synchronized (mLock) {
            switch (mConnectionState) {
              case RUNNING:
                break;
              case STARTING:
              case STOPPING:
              case STOPPING_RESTART_REQUESTED:
              case DISCONNECTED:
                return;
              default:
                throw new IllegalStateException(String.valueOf(mConnectionState));
            }
          }

          String serverHost = AdvancedPreferenceFragment.getMitmServerHost(mContext);
          int serverPort = AdvancedPreferenceFragment.getMitmServerPort(mContext);
          InetSocketAddress serverAddress =
              InetSocketAddress.createUnresolved(serverHost, serverPort);
          Log.i(TAG, "Connecting to " + serverAddress);
          notifyConnecting(serverAddress);
          socket = connectSocket(serverHost, serverPort);
          Log.i(TAG, "Connected to " + serverAddress + ". Upgrading to TLS");
          SSLSocket sslSocket =
              (SSLSocket) mSSLSocketFactory.createSocket(socket, serverHost, serverPort, true);
          tryEnableSni(sslSocket, serverHost);
          tryEnableSessionTickets(sslSocket);
          socket = sslSocket;
          sslSocket.setSoTimeout(TLS_HANDSHAKE_TIMEOUT_MILLIS);
          sslSocket.setUseClientMode(true);
          sslSocket.startHandshake();
          SSLSession sslSession = sslSocket.getSession();
          if (!sslSession.isValid()) {
            throw new SSLException("TLS/SSL handshake failed");
          }
          // No need to verify that server certificate matches the hostname to which we're
          // connecting because of the current trust model where the user is prompted whether to
          // accept an unknown server certificate based on its public key.
          Log.i(TAG, "Upgraded to " + sslSession.getProtocol() + " " + sslSession.getCipherSuite());

          Socket oldSocket;
          synchronized (mLock) {
            switch (mConnectionState) {
              case RUNNING:
                oldSocket = mSocket;
                mSocket = socket;
                break;
              default:
                return;
            }
          }
          Closeables.closeQuietly(oldSocket);

          notifyConnected(serverAddress);
          resetRetryState();
          mConnectionHandler.handleConnection(socket);
        } catch (IOException e) {
          Closeables.closeQuietly(socket);
          socket = null;

          synchronized (mLock) {
            if (mConnectionState != ConnectionState.RUNNING) {
              Log.w(TAG, "Failed to communicate with server -- shutting down", e);
              return;
            } else {
              Log.w(TAG, "Failed to communicate with server", e);
            }
          }

          // Wait (with exponential backoff) and retry
          long delayMillis = getAndIncrementRetryDelay();
          Throwable cause = e.getCause();
          // Notify if the connection failed because of an unknown certificate
          if (cause != null
              && cause instanceof PreferencesBackedPinningX509TrustManager
                .UnknownCertificateException) {
            X509Certificate certificate = ((PreferencesBackedPinningX509TrustManager
                  .UnknownCertificateException) cause).certificate;
            notifyUnknownCertificate(certificate);
          }
          Log.d(TAG, "Sleeping for " + (delayMillis / 1000) + " seconds before retrying");
          notifyWaitingToRetry(e.getMessage(), delayMillis);
          try {
            Thread.sleep(delayMillis);
          } catch (InterruptedException e2) {
            synchronized (mLock) {
              if (mConnectionState != ConnectionState.RUNNING) {
                return;
              }
            }
            continue;
          }
        } finally {
          Closeables.closeQuietly(socket);
        }
      }
    } finally {
      Log.i(TAG, "Stopped");
      synchronized (mLock) {
        switch (mConnectionState) {
          case STOPPING_RESTART_REQUESTED:
            setConnectionState(ConnectionState.DISCONNECTED);
            start();
            break;
          case RUNNING:
          case STARTING:
          case DISCONNECTED:
          case STOPPING:
            setConnectionState(ConnectionState.DISCONNECTED);
            break;
          default:
            throw new IllegalStateException(String.valueOf(mConnectionState));
        }
      }
      notifyStopped();
    }
  }

  private static Socket connectSocket(String host, int port) throws IOException {
    // If HTTPS proxy is set, connect through that proxy instead of connecting directly.
    URI serverUri = URI.create("https://" + host + ":" + port);
    ProxySelector proxySelector = ProxySelector.getDefault();
    List<Proxy> proxies = proxySelector.select(serverUri);
    if ((proxies == null) || (proxies.isEmpty())) {
      proxies = Collections.singletonList(Proxy.NO_PROXY);
    }

    IOException lastFailure = null;
    for (Proxy proxy : proxies) {
      SocketAddress proxyAddress = proxy.address();
      try {
        if (Proxy.NO_PROXY.equals(proxy)) {
          // Direct connection
          return connectSocketNoProxy(host, port);
        } else if (proxy.type() == Proxy.Type.HTTP) {
          // HTTP proxy CONNECT
          return connectSocketViaHttpProxyConnectMethod(host, port, proxyAddress);
        } else {
          // Unsupported proxy type -- ignore
        }
      } catch (IOException e) {
        lastFailure = e;
        if (proxyAddress != null) {
          proxySelector.connectFailed(serverUri, proxyAddress, e);
        }
      }
    }

    if (lastFailure != null) {
      throw lastFailure;
    }
    throw new IOException(
        "No suitable connection methods found for " + serverUri + ": " + proxies);
  }

  /**
   * Connects to the specified destination directly, without going through any non-transparent
   * proxies.
   */
  private static Socket connectSocketNoProxy(String host, int port) throws IOException {
    Log.d(TAG, "Connecting to " + host + ":" + port + " directly");
    Socket socket = new Socket();
    boolean success = false;
    try {
      SocketAddress address = new InetSocketAddress(host, port);
      socket = new Socket();
      socket.connect(address, SERVER_CONNECT_TIMEOUT_MILLIS);
      success = true;
      return socket;
    } finally {
      if (!success) {
        Closeables.closeQuietly(socket);
      }
    }
  }

  /**
   * Connects to the specified destination using the {@code HTTP CONNECT} method of the specified
   * HTTP proxy.
   */
  private static Socket connectSocketViaHttpProxyConnectMethod(
      String host, int port, SocketAddress proxyAddress) throws IOException {
    Log.d(TAG, "Connecting to " + host + ":" + port + " via HTTP proxy " + proxyAddress);
    Socket socket = new Socket();
    boolean success = false;
    try {
      // The proxyAddress might not yet been resolved -- resolve it if necessary.
      InetSocketAddress proxyInetAddress = (InetSocketAddress) proxyAddress;
      if (proxyInetAddress.isUnresolved()) {
        proxyInetAddress = new InetSocketAddress(
            proxyInetAddress.getHostName(),
            proxyInetAddress.getPort());
      }
      socket = new Socket();
      socket.connect(proxyInetAddress, HTTP_PROXY_CONNECT_TIMEOUT_MILLIS);
      BufferedWriter out = new BufferedWriter(new OutputStreamWriter(
          socket.getOutputStream(), "US-ASCII"));
      out.write("CONNECT " + host + ":" + port + " HTTP/1.1\r\n");
      out.write("Host: " + host + ":" + port + "\r\n");
      out.write("\r\n");
      out.flush();

      // Buffered reading below assumes that the protocol which will run after HTTP CONNECT
      // is such that the server does not transmit anything until the client transmits something.
      // Otherwise we might over-read here.
      BufferedReader in = new BufferedReader(new InputStreamReader(
          socket.getInputStream(), "US-ASCII"));
      String line;
      boolean statusLineRead = false;
      boolean responseHeadersRead = false;
      socket.setSoTimeout(SERVER_CONNECT_TIMEOUT_MILLIS);
      while ((line = in.readLine()) != null) {
        if (!statusLineRead) {
          String[] tokens = line.split("\\s+", 3);
          if (tokens.length != 3) {
            throw new IOException("Unexpected reply from HTTP proxy: " + line);
          }
          String httpVersion = tokens[0];
          String statusCodeString = tokens[1];
          String reason = tokens[2];
          if (!httpVersion.startsWith("HTTP/1.")) {
            throw new IOException("Unsupported HTTP version in HTTP proxy response: " + line);
          }
          if (!"200".equals(statusCodeString)) {
            throw new IOException(
                "HTTP proxy CONNECT failed. Status: " + statusCodeString + ", reason: " + reason);
          }
          statusLineRead = true;
          continue;
        }
        if (line.length() == 0) {
          responseHeadersRead = true;
          break;
        }
      }

      if (!statusLineRead) {
        throw new EOFException("Empty response from HTTP proxy");
      }
      if (!responseHeadersRead) {
        throw new EOFException("Premature end of stream while reading HTTP proxy response");
      }

      success = true;
      return socket;
    } finally {
      if (!success) {
        Closeables.closeQuietly(socket);
      }
    }
  }

  private void resetRetryState() {
    synchronized (mLock) {
      mNextDelayMillis = 0;
    }
  }

  private long getAndIncrementRetryDelay() {
    // IMPLEMENTATION NOTE: Randomized exponential backoff works by doubling a non-randomized delay
    // (mean) around which randomization (half a mean in each direction) is applied.

    long mean;
    synchronized (mLock) {
      mean = mNextDelayMillis;
      if (mean == 0) {
        mean = MIN_DELAY_MILLIS;
      } else {
        mean *= 2;
        if (mNextDelayMillis > MAX_DELAY_MILLIS) {
          mean = MAX_DELAY_MILLIS;
        }
      }
      mNextDelayMillis = mean;
    }

    // Return a random value (uniform distribution) from
    // mean / 2 + [-mean / 2; +mean / 2).
    return (long) ((mean / 2) + (mRng.nextDouble() * mean));
  }

  private void notifyStarted() {
    synchronized (mLock) {
      mLastStateChangeEvent = new StateChangeEvent(StateChangeEventType.STARTED);
    }
    for (StateChangeListener listener : mStateChangeListeners) {
      listener.onStarted();
    }
  }

  private void notifyStopped() {
    synchronized (mLock) {
      mLastStateChangeEvent = new StateChangeEvent(StateChangeEventType.STOPPED);
    }
    for (StateChangeListener listener : mStateChangeListeners) {
      listener.onStopped();
    }
  }

  private void notifyWaitingToRetry(String cause, long delayMillis) {
    synchronized (mLock) {
      mLastStateChangeEvent =
          new StateChangeEvent(StateChangeEventType.WAITING_TO_RETRY, cause, delayMillis);
    }
    for (StateChangeListener listener : mStateChangeListeners) {
      listener.onWaitingToRetry(cause, delayMillis);
    }
  }

  private void notifyConnecting(InetSocketAddress address) {
    synchronized (mLock) {
      mLastStateChangeEvent = new StateChangeEvent(StateChangeEventType.CONNECTING, address);
    }
    for (StateChangeListener listener : mStateChangeListeners) {
      listener.onConnecting(address);
    }
  }

  private void notifyConnected(InetSocketAddress address) {
    synchronized (mLock) {
      mLastStateChangeEvent = new StateChangeEvent(StateChangeEventType.CONNECTED, address);
    }
    for (StateChangeListener listener : mStateChangeListeners) {
      listener.onConnected(address);
    }
  }

  private void notifyUnknownCertificate(X509Certificate certificate) {
    synchronized (mLock) {
      mLastStateChangeEvent = new StateChangeEvent(StateChangeEventType.UNKNOWN_CERTIFICATE,
          certificate);
    }
    for (StateChangeListener listener : mStateChangeListeners) {
      listener.onUnknownCertificate(certificate);
    }
  }

  private void notifyEvent(StateChangeListener listener, StateChangeEvent event) {
    if ((listener == null) || (event == null)) {
      return;
    }
    switch (event.mType) {
      case STARTED:
        listener.onStarted();
        break;
      case STOPPED:
        listener.onStopped();
        break;
      case CONNECTING:
        listener.onConnecting(event.mAddress);
        break;
      case CONNECTED:
        listener.onConnected(event.mAddress);
        break;
      case WAITING_TO_RETRY:
        listener.onWaitingToRetry(event.mCause, event.mDelayMillis);
        break;
      case UNKNOWN_CERTIFICATE:
        listener.onUnknownCertificate(event.mCertificate);
        break;
      default:
        throw new IllegalArgumentException("Unknown event type: " + event.mType);
    }
  }

  public void whitelistCertificate(X509Certificate certificate) {
    mTrustManager.whitelist(certificate.getPublicKey());
  }

  public void blacklistCertificate(X509Certificate certificate) {
    mTrustManager.blacklist(certificate.getPublicKey());
  }

  private static void tryEnableSni(SSLSocket socket, String hostname) throws IOException {
    try {
      socket.getClass().getMethod("setHostname", String.class).invoke(socket, hostname);
    } catch (NoSuchMethodException e) {
      // setHostname method does not exist
      e.printStackTrace();
    } catch (IllegalAccessException e) {
      // setHostname method is not public or not accessible via Reflection API
      e.printStackTrace();
    } catch (InvocationTargetException e) {
      throw new IOException("Failed to enable SNI via Reflection API", e);
    }
  }

  private static void tryEnableSessionTickets(SSLSocket socket) throws IOException {
    try {
      socket.getClass().getMethod("setUseSessionTickets", boolean.class).invoke(socket, true);
    } catch (NoSuchMethodException e) {
      // setUseSessionTickets method does not exist
      e.printStackTrace();
    } catch (IllegalAccessException e) {
      // setUseSessionTickets method is not public or not accessible via Reflection API
      e.printStackTrace();
    } catch (InvocationTargetException e) {
      throw new IOException("Failed to enable session tickets via Reflection API", e);
    }
  }
}
