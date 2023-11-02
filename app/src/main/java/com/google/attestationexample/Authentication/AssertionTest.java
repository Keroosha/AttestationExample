package com.google.attestationexample.Authentication;

import android.os.AsyncTask;
import android.widget.TextView;

import java.io.PrintWriter;
import java.io.StringWriter;

public class AssertionTest extends AsyncTask<Void, String, Void> {

    private final TextView view;
    private final String packageName;

    public AssertionTest(TextView view, String packageName) {
        this.view = view;
        this.packageName = packageName;
    }
    @Override
    protected Void doInBackground(Void... params) {
        try {
            GenerateAndroidKeyAssertion();
        } catch (Exception e) {
            StringWriter s = new StringWriter();
            e.printStackTrace(new PrintWriter(s));
            publishProgress(s.toString());
        }
        return null;
    }

    @Override
    protected void onProgressUpdate(String... values) {
        for (String value : values) {
            view.append(value);
        }
    }

    private void GenerateAndroidKeyAssertion() throws Exception {
        String authenticationResponseJson = "123";
        publishProgress(authenticationResponseJson);
        System.out.println(authenticationResponseJson);
    }
}
