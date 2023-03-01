import React from "react";

export const Esteban = () => {

  const endpoint = '/agents?select=lastKeepAlive&select=id&status=active'

  const protocol = 'https'
  const host = '54.145.241.208'
  const port = '55000'
  const user = 'wazuh-wui'
  const password = 'uvVZM6eL1tb.1VELhQ1SxUo7RxUauw+N'

  var credentials = btoa("wazuh-wui:uvVZM6eL1tb.1VELhQ1SxUo7RxUauw+N");
  var auth = { "Authorization": `Basic ${credentials}` };

  const base_url = `${protocol}://${host}:${port}`
  const login_url = `${base_url}/security/user/authenticate`
  const basic_auth = `${user}:${password}`

  fetch("https://54.145.241.208:55000/security/user/authenticate", {
    headers: auth
  })
    .then(response => console.log(response))
    .then(data => console.log(data));

  /* const token = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3YXp1aCIsImF1ZCI6IldhenVoIEFQSSBSRVNUIiwibmJmIjoxNjc3NzA4ODcwLCJleHAiOjE2Nzc3MDk3NzAsInN1YiI6IndhenVoLXd1aSIsInJ1bl9hcyI6ZmFsc2UsInJiYWNfcm9sZXMiOlsxXSwicmJhY19tb2RlIjoid2hpdGUifQ.AY3IixR6nAmFoLgPlvT2yXgiIckHjykgjR0CTGvwM8LGAh528l0rBfKDtioU26ZW_kFW8ivaIQzKuZ0PlrkkVeCEAVq8vPuHr5RB0oRV87cp8mHkfPeyaWCKEdmwhTT8hnoD6o8W386IxSFBv3frcV8_KNpwUU-zP16zq9KP0e3Iv-CS"

  fetch("https://54.145.241.208:55000/agents", {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  })
    .then(response => console.log(response))
    .then(data => console.log(data)); */

  return <div>Esteban</div>;
};
