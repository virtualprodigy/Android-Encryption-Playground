package com.virtualprodigy.androidencryptionplayground;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.ResultReceiver;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.virtualprodigy.androidencryptionplayground.services.EncrypterService;

public class MainActivity extends AppCompatActivity {

    EditText userInputET;
    TextView encryptedTV, decryptedTV;
    Button encryptBttn;
    Context context;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        this.context = this;
        initViewWidgets();
    }

    /**
     * Handles associating the views with the local properties
     */
    private void initViewWidgets() {
        userInputET = (EditText) findViewById(R.id.userInput);
        encryptedTV = (TextView) findViewById(R.id.encryptedTextView);
        decryptedTV = (TextView) findViewById(R.id.decryptedTextView);
        encryptBttn = (Button) findViewById(R.id.startEncryptionBttn);

        encryptBttn.setOnClickListener(encryptListener);
    }

    View.OnClickListener encryptListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            //get the user's text value
            String userInputVal = userInputET.getText().toString();

            Intent intent = new Intent(context, EncrypterService.class);
            intent.setAction(EncrypterService.ACTION_ENCRYPT_DATA);
            Bundle bundle = new Bundle();
            bundle.putString(EncrypterService.BUNDLE_MASTER_KEY, "1234");
            bundle.putString(EncrypterService.BUNDLE_DATA_TO_ENCRYPT, userInputVal);
            bundle.putParcelable(EncrypterService.BUNDLE_RESULT_RECEIVER, resultReceiver);
            intent.putExtras(bundle);
            startService(intent);

        }

    };

    ResultReceiver resultReceiver = new ResultReceiver(new Handler()){
        @Override
        protected void onReceiveResult(int resultCode, Bundle resultData) {
            super.onReceiveResult(resultCode, resultData);

            if(resultCode == EncrypterService.RESULT_CODE_ENCRYPT_OK){
                String encryptedData = resultData.getString(EncrypterService.BUNDLE_ENCRYPTED_DATA);
                encryptedTV.setText(encryptedData);

                //TODO for testing purposes; Decrypt the data
                Intent intent = new Intent(context, EncrypterService.class);
                intent.setAction(EncrypterService.ACTION_DECRYPT_DATA);
                Bundle bundle = new Bundle();
                bundle.putString(EncrypterService.BUNDLE_MASTER_KEY, "1234");
                bundle.putString(EncrypterService.BUNDLE_DATA_TO_DECRYPT, encryptedData);
                bundle.putParcelable(EncrypterService.BUNDLE_RESULT_RECEIVER, resultReceiver);
                intent.putExtras(bundle);
                startService(intent);
            }else if(resultCode == EncrypterService.RESULT_CODE_DECRYPT_OK){
                String decryptedData = resultData.getString(EncrypterService.BUNDLE_DECRYPTED_DATA);
                decryptedTV.setText(decryptedData);
            }
        }
    };

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
