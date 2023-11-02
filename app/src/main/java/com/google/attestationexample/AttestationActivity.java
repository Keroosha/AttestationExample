package com.google.attestationexample;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.view.Menu;
import android.widget.TextView;

import com.google.attestationexample.Authentication.AssertionTest;
import com.google.attestationexample.Registration.AttestationTest;

public class AttestationActivity extends AppCompatActivity {
    public static String PACKAGE_NAME;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_attestation);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton attestationFab = (FloatingActionButton) findViewById(R.id.fabLoadAttestation);
        FloatingActionButton assertionFab = (FloatingActionButton) findViewById(R.id.fabLoadAssertion);
        FloatingActionButton fabCopy = (FloatingActionButton) findViewById(R.id.fabCopy);
        attestationFab.setOnClickListener(view -> createAttestationResponse());
        assertionFab.setOnClickListener(view -> createAssertionResponse());
        fabCopy.setOnClickListener(view -> copy());
        ((TextView) findViewById(R.id.textview)).setMovementMethod(new ScrollingMovementMethod());
        PACKAGE_NAME = getApplicationContext().getPackageName();
    }

    private void createAttestationResponse() {
        TextView textView = (TextView) findViewById(R.id.textview);
        textView.setText("");
        try {
            new AttestationTest(textView, PACKAGE_NAME).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createAssertionResponse() {
        TextView textView = (TextView) findViewById(R.id.textview);
        textView.setText("");
        try {
            new AssertionTest(textView, PACKAGE_NAME).execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void copy() {
        TextView textView = (TextView) findViewById(R.id.textview);
        String text = textView.getText().toString();
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Copied Text", text);
        clipboard.setPrimaryClip(clip);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_attestation, menu);
        return true;
    }
}
