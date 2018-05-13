package com.edwardlu.pretenddeviceapplication;

import android.app.Service;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Binder;
import android.os.IBinder;
import android.provider.ContactsContract;
import android.support.annotation.Nullable;
import android.util.Log;

import com.edwardlu.pretenddeviceapplication.MainActivity;

import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnRegisterSuccess;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.security.identity.IdentityManager;
import net.named_data.jndn.security.identity.MemoryIdentityStorage;
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;

import java.io.IOException;
import java.security.Identity;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class NFDService extends Service {

    private static String TAG = "NFDService";

    // strings for the intent filter
    public final static String NFD_STOPPED = "NFD_STOPPED";
    public final static String FACE_CLOSED = "FACE_CLOSED";
    public final static String INTEREST_RECEIVED = "INTEREST_RECEIVED";
    public final static String DATA_RECEIVED = "DATA_RECEIVED";
    public final static String INTEREST_SENT = "INTEREST_SENT";
    public final static String INTEREST_TIMEOUT = "INTEREST_TIMEOUT";
    public final static String INTEREST_NACK = "INTEREST_NACK";
    public final static String INTEREST_EXCEPTION = "INTEREST_EXCEPTION";

    // strings for intent extras
    public final static String NAME = "NAME";

    private Face face;
    private KeyChain keyChain;
    boolean alreadyRunning;

    @Override
    public void onDestroy() {
        Log.d(TAG, "we got told to destroy ourselves");
        super.onDestroy();
        face.shutdown();
        networkThread.interrupt();
    }

    public void startNetworkThread() {
        if (!alreadyRunning) {
            networkThread.start();
        }
    }

    private void registerDataPrefix () {
        Log.d(TAG, "registering prefixes...");
        try {
            face.registerPrefix(new Name("/fakeDevice"), OnInterest, OnPrefixRegisterFailed, OnPrefixRegisterSuccess);
        } catch (IOException | SecurityException e) {
            // should also be handled in callback, but in just in case...
        }
    }

    private final OnInterestCallback OnInterest = new OnInterestCallback() {
        @Override
        public void onInterest(Name prefix, Interest interest, final Face face, long interestFilterId, InterestFilter filter) {

            Log.d(TAG, "Got interest: " + interest.getName().toString());

        }
    };

    private final OnRegisterSuccess OnPrefixRegisterSuccess = new OnRegisterSuccess() {
        @Override
        public void onRegisterSuccess(Name prefix, long registeredPrefixId) {
            Log.d(TAG, "successfully registered data prefix: " + prefix);
        }
    };

    private final OnRegisterFailed OnPrefixRegisterFailed = new OnRegisterFailed() {
        @Override
        public void onRegisterFailed(Name prefix) {
            Log.d(TAG, "we failed to register the data prefix: " + prefix);
        }
    };

    private void initializeKeyChain() {
        Log.d(TAG, "initializing keychain");
        MemoryIdentityStorage identityStorage = new MemoryIdentityStorage();
        MemoryPrivateKeyStorage privateKeyStorage = new MemoryPrivateKeyStorage();
        IdentityManager identityManager = new IdentityManager(identityStorage, privateKeyStorage);
        keyChain = new KeyChain(identityManager);
        keyChain.setFace(face);
    }

    private void setCommandSigningInfo() {
        Log.d(TAG, "setting command signing info");
        Name defaultCertificateName;
        try {
            defaultCertificateName = keyChain.getDefaultCertificateName();
        } catch (SecurityException e) {
            Log.d(TAG, "unable to get default certificate name");

            // NOTE: This is based on apps-NDN-Whiteboard/helpers/Utils.buildTestKeyChain()...
            Name testIdName = new Name("/test/identity");
            try {
                defaultCertificateName = keyChain.createIdentityAndCertificate(testIdName);
                keyChain.getIdentityManager().setDefaultIdentity(testIdName);
                Log.d(TAG, "created default ID: " + defaultCertificateName.toString());
            } catch (SecurityException e2) {
                defaultCertificateName = new Name("/controller/certificate/name");
            }
        }
        face.setCommandSigningInfo(keyChain, defaultCertificateName);
    }

    public void expressInterest(String dataName) {

        Log.d(TAG + " actual string data ", dataName);

        Name name = new Name(dataName);

        Log.d(TAG, name.toString());

        expressInterest(name);
    }

    private void expressInterest(Name dataName) {
        Log.d(TAG, "expressing interest for " + dataName.toString());

        class OneShotTask implements Runnable {
            Name name;

            OneShotTask(Name n) {
                name = n;
            }

            public void run() {
                try {
                    Interest interest = new Interest(name);

                    interest.setMustBeFresh(true);

                    interest.setInterestLifetimeMilliseconds(1000);

                    face.expressInterest(interest, OnReceivedData,
                            OnInterestTimeout, OnInterestNack);

                    sendBroadcastName(INTEREST_SENT, name.toString());

                } catch (IOException e) {

                    sendBroadcastName(INTEREST_EXCEPTION, name.toString());

                    Log.d(TAG, "failure when responding to interest: " + e.toString());
                }
            }
        }
        Thread t = new Thread(new OneShotTask(dataName));
        t.start();

    }

    private final Thread networkThread = new Thread(new Runnable() {

        @Override
        public void run () {
            Log.d(TAG, "network thread started");
            try {
                face = new Face("localhost");
                initializeKeyChain();
                setCommandSigningInfo();
                registerDataPrefix();
            } catch (Exception e) {
                //raiseError("error during network thread initialization",
                //ErrorCode.OTHER_EXCEPTION, e);
            }
            while (!alreadyRunning) {
                try {
                    face.processEvents();
                    Thread.sleep(100); // avoid hammering the CPU
                } catch (IOException e) {
                    //raiseError("error in processEvents loop", ErrorCode.NFD_PROBLEM, e);
                } catch (Exception e) {
                    //raiseError("error in processEvents loop", ErrorCode.OTHER_EXCEPTION, e);
                }
            }
            doFinalCleanup();
            //handleAnyRaisedError();
            Log.d(TAG, "network thread stopped");


        }
    });

    private final IBinder mBinder = new NFDService.LocalBinder();

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {

        return mBinder;
    }

    public class LocalBinder extends Binder {
        NFDService getService() {
            return NFDService.this;
        }
    }

    public static IntentFilter getIntentFilter() {
        IntentFilter filter = new IntentFilter();
        filter.addAction(NFD_STOPPED);
        filter.addAction(FACE_CLOSED);
        filter.addAction(INTEREST_RECEIVED);
        filter.addAction(DATA_RECEIVED);
        filter.addAction(INTEREST_SENT);
        filter.addAction(INTEREST_TIMEOUT);
        filter.addAction(INTEREST_NACK);
        filter.addAction(INTEREST_EXCEPTION);
        return filter;
    }

    private void broadcastUpdate(final String action) {
        final Intent intent = new Intent(action);
        sendBroadcast(intent);
    }

    private void doFinalCleanup() {
        Log.d(TAG, "cleaning up and resetting service...");
        if (face != null) face.shutdown();
        face = null;
        Log.d(TAG, "service cleanup/reset complete");
    }



    private final OnData OnReceivedData = new OnData() {
        @Override
        public void onData(Interest interest, Data data) {
            Name name = data.getName();
            String content = data.getContent().toString();
            Log.d(TAG, "received data for " + name);

            if (data.getName().toString().contains("/ndn/sign-on")) {
                Log.d(TAG, "got bootstrapping data");
                Blob dataContent = data.getContent();

            }

            sendBroadcastName(DATA_RECEIVED, name.toString());
        }
    };

    private final OnTimeout OnInterestTimeout = new OnTimeout() {
        @Override
        public void onTimeout(Interest interest) {
            Name name = interest.getName();
            sendBroadcastName(INTEREST_TIMEOUT, name.toString());
            Log.d(TAG, "timed out waiting for " + name);
        }
    };

    private final OnNetworkNack OnInterestNack = new OnNetworkNack() {
        @Override
        public void onNetworkNack(Interest interest, NetworkNack networkNack) {
            Name name = interest.getName();
            sendBroadcastName(INTEREST_NACK, name.toString());
            Log.d(TAG, "received NACK for " + name);
        }
    };

    void sendBroadcastName (String broadcastName, String name) {
        Intent intent = new Intent(broadcastName);

        intent.putExtra(NAME, name);

        sendBroadcast(intent);
    }
}