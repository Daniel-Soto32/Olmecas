import React from "react";
export const Dany = () => {

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
    mode: 'no-cors',
    headers: auth
  })
    .then(response => console.log(response))
    .then(data => console.log(data));

  return(
    <div>
        <div class="container" style="back">
          <div>
            <h1>El Dani</h1>
          </div>
      </div>
      


    </div>
  )
}