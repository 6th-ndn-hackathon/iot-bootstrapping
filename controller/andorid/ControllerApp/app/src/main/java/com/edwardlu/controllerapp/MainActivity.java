package com.edwardlu.controllerapp;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.pib.detail.PibIdentityImpl;
import net.named_data.jndn.security.pib.detail.PibKeyImpl;
import net.named_data.jndn.security.tpm.Tpm;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

//implementing onclicklistener
public class MainActivity extends AppCompatActivity{

    public static String TAG = "MainActivity";

    public static String DEVICE_SCANNED = "DEVICE_SCANNED";

    //View Objects
    private Button buttonScan;
    private Button testButton;
    private TextView scanResultsDisplay;

    //qr code scanner object
    private IntentIntegrator qrScan;

    // hardcoded certificate for the arduino
    String arduinoCertificate = "Bv0BVQdACAZpb3QtYXIIA0tFWQggAWLqucA7vqa6y76fAAcvrtx6bfKRy51/MktT" +
            "QTqbiWkIBHNlbGYICf0AAAFjTfV/hxQJGAECGQQANu6AFVswWTATBgcqhkjOPQIB" +
            "BggqhkjOPQMBBwNCAASj6NM8J8Kg+/Ecd/grHrOkM852Tvozv0Epel/53g2HHBmQ" +
            "HvstxcGvw/aduSI2aSsm0+jszf1uq+JmdEgMVYN9FmAbAQMcMQcvCAZpb3QtYXII" +
            "A0tFWQggAWLqucA7vqa6y76fAAcvrtx6bfKRy51/MktTQTqbiWn9AP0m/QD+DzE5" +
            "NzAwMTAxVDAwMDAwMP0A/w8yMDM4MDUwNlQwNjQ4NDQXRzBFAiB6wAOPD8uSNwzA" +
            "rITtcc4U8SY+k4oHBOuCb6RA9jcqJgIhAL1Yqy6ncLq6iiV/rm1dDncqwlxQrCq9" +
            "JjM5rV+gUKKW";

    // hardcoded certificate for the raspberry pi
    String piCertificate = "Bv0BVQdACAZpb3QtcGkIA0tFWQggbAWiGilAAp03KIPDm//wBGvjjXVxMZNWoxDQ" +
            "PwTC4gsIBHNlbGYICf0AAAFjTffXLRQJGAECGQQANu6AFVswWTATBgcqhkjOPQIB" +
            "BggqhkjOPQMBBwNCAASqM97WXsB9u0CI4XkUNv1oHtpZD9fdUwtSUChSWjdSUHje" +
            "d9g7BoPOWNkzXDAJ+1pBpKfwE0K8LtajWhofkdnPFmAbAQMcMQcvCAZpb3QtcGkI" +
            "A0tFWQggbAWiGilAAp03KIPDm//wBGvjjXVxMZNWoxDQPwTC4gv9AP0m/QD+DzE5" +
            "NzAwMTAxVDAwMDAwMP0A/w8yMDM4MDUwNlQwNjUxMTgXRzBFAiBFiYuCQ5FbtcZS" +
            "VJiBfDP95gqbef6nuPILoWHNX1RdWwIhAJikHipQe6Rw9Kje5rHNXf/OkI5R6riW" +
            "xUAXwfFIARMh";

    String lastScanResult = "";

    NFDService nfdService;

    public static CertificateV2 lastDeviceCertificate;
    public static String lastBKpubDigest;

    BroadcastReceiver scanSignalListener = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();

            if (action.equals(MainActivity.DEVICE_SCANNED)) {

                Log.d(TAG, "got signal that device was scanned");

                //nfdService.devices.put(MainActivity.lastBKpubDigest, new NFDService.DeviceInfo(MainActivity.lastDeviceCertificate, 0));

            }
        }
    };

    private final ServiceConnection nfdServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.d(TAG, "onServiceConnected for nfdServiceConnection got called.");
            nfdService = ((NFDService.LocalBinder) service).getService();

            nfdService.startNetworkThread();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            nfdService = null;
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        registerReceiver(scanSignalListener, getIntentFilter());

        // display for scan results
        scanResultsDisplay = (TextView) findViewById(R.id.scanResultsDisplay);

        //intializing scan object
        qrScan = new IntentIntegrator(this);

        // button to start scan
        buttonScan = (Button) findViewById(R.id.buttonScan);
        buttonScan.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                qrScan.initiateScan();
            }
        });

        testButton = (Button) findViewById(R.id.testButton);
        testButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (nfdService == null) {
                    Log.d(TAG, "nfd service was null");
                }
                else {
                    Log.d(TAG, "nfd service was not null");
                }

                if (nfdService.devices == null) {
                    Log.d(TAG, "nfd devices was null");
                }
                else {
                    Log.d(TAG, "nfd devices was not null");
                }

                nfdService.devices.put(MainActivity.lastBKpubDigest, new NFDService.DeviceInfo(MainActivity.lastDeviceCertificate, 0));

                Log.d(TAG, nfdService.devices.get(lastBKpubDigest).BKpub.getIdentity().toString());

                if (nfdService == null ) {
                    Log.d(TAG, "nfd service was null");
                }
                if (nfdService.keyChain == null) {
                    Log.d(TAG, "nfd keychain was null");
                }

                try {
                    PibIdentity BKIdentity = nfdService.keyChain.createIdentityV2(new Name("BKIdentity"));
                } catch (PibImpl.Error error) {
                    error.printStackTrace();
                } catch (Pib.Error error) {
                    error.printStackTrace();
                } catch (Tpm.Error error) {
                    error.printStackTrace();
                } catch (TpmBackEnd.Error error) {
                    error.printStackTrace();
                } catch (KeyChain.Error error) {
                    error.printStackTrace();
                }
            }
        });

        // starts the nfd service
        Intent nfdIntent = new Intent(MainActivity.this, NFDService.class);
        boolean test = bindService(nfdIntent, nfdServiceConnection, BIND_AUTO_CREATE);
        if (test) {
            Log.d(TAG, "bindService for nfdService was successful");
        } else {
            Log.d(TAG, "bindService for nfdService was not successful");
        }

        /*
        // /[home-prefix]/cert/Hash(BKpub)/{CKpub}/{signature of token2}/{signature by BKpri}
        Interest request = new Interest(new Name("/home-prefix/cert/HashOfBKpub/CKpub/signature of token2/signature by BKpri"));
        Name name = request.getName();
        Name.Component signatureOfToken2 = name.get(-2);
        Name.Component CKpub = name.get(-3);
        Name.Component BKpubHash = name.get(-4);

        Log.d(TAG, name.toString());
        Log.d(TAG, signatureOfToken2.toEscapedString());
        Log.d(TAG, CKpub.toEscapedString());
        Log.d(TAG, BKpubHash.toEscapedString());
        */

    }

    // get the scan results
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null) {

            if (result.getContents().equals(arduinoCertificate) || result.getContents().equals(piCertificate)) {

                String scanResults = result.getContents();

                scanResultsDisplay.setText(scanResults);

                lastScanResult = scanResults;

                byte[] decodeData = Common.base64Decode(scanResults);
                Data keyDataPacket = new Data();
                try {
                    keyDataPacket.wireDecode(new Blob(decodeData));
                } catch (EncodingException e) {
                    e.printStackTrace();
                }

                CertificateV2 deviceCertificate = null;

                try {
                    deviceCertificate = new CertificateV2(keyDataPacket);
                } catch (CertificateV2.Error error) {
                    error.printStackTrace();
                }

                Blob deviceCertificateContent = deviceCertificate.getContent();
                byte[] deviceCertificateContentBytes = deviceCertificateContent.getImmutableArray();

                MessageDigest sha256;
                try {
                    sha256 = MessageDigest.getInstance("SHA-256");
                } catch (NoSuchAlgorithmException exception) {
                    // Don't expect this to happen.
                    throw new Error
                            ("MessageDigest: SHA-256 is not supported: " + exception.getMessage());
                }

                sha256.update(deviceCertificateContentBytes);
                byte[] digestBytes = sha256.digest();
                Blob digestBlob = new Blob(digestBytes);
                String digestString = digestBlob.toHex();

                Log.d(TAG, "digest of public key of certificate scanned from qr code: " + digestString);

                lastBKpubDigest = digestString;
                lastDeviceCertificate = deviceCertificate;

                sendBroadcast(new Intent(DEVICE_SCANNED));

                if (nfdService == null) {
                    Log.d(TAG, "nfd service is null from scan results activity");
                }

                if (result.getContents().equals(arduinoCertificate)) {
                    Toast.makeText(this, "qr code matched what we expected for arduino", Toast.LENGTH_LONG).show();
                } else if (result.getContents().equals(piCertificate)) {
                    Toast.makeText(this, "qr code matched what we expected for raspberry pi", Toast.LENGTH_LONG).show();

                } else {
                    Toast.makeText(this, "qr code did not match arduino or raspberry pi", Toast.LENGTH_LONG).show();
                }
            }
        }

        else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    public static IntentFilter getIntentFilter() {
        IntentFilter intentFilter = new IntentFilter();

        intentFilter.addAction(DEVICE_SCANNED);

        return intentFilter;
    }

    @Override
    protected void onDestroy() {

        unregisterReceiver(scanSignalListener);

        unbindService(nfdServiceConnection);

        super.onDestroy();
    }
}
