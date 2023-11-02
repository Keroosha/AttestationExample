package com.google.attestationexample.Registration.Options;

import java.util.ArrayList;

public class PublicKeyCredentialCreationOptions {
    public PublicKeyCredentialRpEntity rp;
    public PublicKeyCredentialUserEntity user;
    public String challenge;
    public ArrayList<PublicKeyCredentialParameters> pubKeyCredParams;
    public int timeout;
    public String attestation;
    public AuthenticatorSelectionCriteria authenticatorSelection;
}
