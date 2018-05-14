package com.edwardlu.pretenddeviceapplication;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    public static String TAG = "MainActivity";

    public static MainActivity mainActivity;

    private Button bootstrapButton;
    private Button certificateButton;
    private TextView logDisplay;

    NFDService nfdService;

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

    BroadcastReceiver nfdStatusListener = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String receivedSignal = intent.getAction();

            if (receivedSignal.equals(NFDService.INTEREST_SENT)) {
                logDisplay.append("\nSent an interest with name: " + intent.getExtras().getString(NFDService.NAME) + "\n");
            }
            else if (receivedSignal.equals(NFDService.INTEREST_EXCEPTION)) {
                logDisplay.append("\nException for interest sent with name: " + intent.getExtras().getString(NFDService.NAME) + "\n");
            }
            else if (receivedSignal.equals(NFDService.INTEREST_TIMEOUT)) {
                logDisplay.append("\nTimeout for interest sent with name: " + intent.getExtras().getString(NFDService.NAME) + "\n");
            }
            else if (receivedSignal.equals(NFDService.INTEREST_NACK)) {
                logDisplay.append("\nNack for interest sent with name: " + intent.getExtras().getString(NFDService.NAME) + "\n");
            }
            else if (receivedSignal.equals(NFDService.DATA_RECEIVED)) {
                logDisplay.append("\nData recieved with name: " + intent.getExtras().getString(NFDService.NAME) + "\n");
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mainActivity = MainActivity.this;

        registerReceiver(nfdStatusListener, NFDService.getIntentFilter());

        bootstrapButton = (Button) findViewById(R.id.bootstrapButton);
        bootstrapButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // /ndn/sign-on/Hash(BKpub)/{ECDSA signature by BKpri}
                nfdService.expressInterest(
                        "/ndn/sign-on/6C05A21A2940029D372883C39BFFF0046BE38D7571319356A310D03f04C2E20B/BKpriSignature");
            }
        });

        certificateButton = (Button) findViewById(R.id.certificateButton);
        certificateButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // /[home-prefix]/cert/{digest of BKpub}/{CKpub}/{signature of token}/{signature by BKpri}
                nfdService.expressInterest(
                        "/ucla/eiv396/cert/6c05a21a2940029d372883c39bfff0046be38d7571319356a310d03f04c2e20b/CKpub/tokenSignature/BKpriSignature"
                );
            }
        });

        logDisplay = (TextView) findViewById(R.id.log);

        // starts the nfd service
        Intent nfdIntent = new Intent(MainActivity.this, NFDService.class);
        boolean test = bindService(nfdIntent, nfdServiceConnection, BIND_AUTO_CREATE);
        if (test) {
            Log.d(TAG, "bindService for nfdService was successful");
        } else {
            Log.d(TAG, "bindService for nfdService was not successful");
        }
    }

    public static MainActivity getInstance() {
        return mainActivity;
    }

    @Override
    protected void onDestroy() {

        unbindService(nfdServiceConnection);

        unregisterReceiver(nfdStatusListener);

        super.onDestroy();
    }
}
