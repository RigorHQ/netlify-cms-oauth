import { IncomingMessage, ServerResponse } from "http";
import { AuthorizationCode } from "simple-oauth2";
import { config, Provider } from "../lib/config";

export default async (req: IncomingMessage, res: ServerResponse) => {
  const { host } = req.headers;
  const url = new URL(`https://${host}/${req.url}`);
  const urlParams = url.searchParams;
  const code = urlParams.get("code");
  const provider = urlParams.get("provider") as Provider;

  try {
    if (!code) throw new Error(`Missing code ${code}`);

    const client = new AuthorizationCode(config(provider));
    const tokenParams = {
      code,
      redirect_uri: `https://${host}/callback?provider=${provider}`,
    };

    const accessToken = await client.getToken(tokenParams);
    const token = accessToken.token["access_token"] as string;

    const responseBody = renderBody("success", {
      token,
      provider,
    });

    res.statusCode = 200;
    res.end(responseBody);
  } catch (e) {
    res.statusCode = 400;
    res.end(renderBody("error", { error: e.message, provider }));
  }
};

function renderBody(status: "success" | "error", content: any) {
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
   <meta charset="utf-8">
   <title>Authorizing ...</title>
  </head>
  <body>
  <p id="message"></p>
  <script>
   // Output a message to the user
   function sendMessage(message) {
     document.getElementById("message").innerText = message;
     document.title = message
   }

   // Handle a window message by sending the auth to the "opener"
   function receiveMessage(message) {
     console.debug("receiveMessage", message);
     window.opener.postMessage(
       'authorization:${content.provider}:${status}:${JSON.stringify(content)}',
       message.origin
     );
     window.removeEventListener("message", receiveMessage, false);
     sendMessage("Authorized, closing ...");
   }

   sendMessage("Authorizing ...");
   window.addEventListener("message", receiveMessage, false);

   console.debug("postMessage", "authorizing:${content.provider}", "*")
   window.opener.postMessage("authorizing:${content.provider}", "*");
  </script>
  </body>
  </html>
  `;
}
