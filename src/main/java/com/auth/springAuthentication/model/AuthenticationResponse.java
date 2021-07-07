package com.auth.springAuthentication.model;

public class AuthenticationResponse {
	
	private String jwtToken;

	public String getJwtToken() {
		return jwtToken;
	}

	public AuthenticationResponse(String jwt) {
        this.jwtToken = jwt;
    }
	

}
