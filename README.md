# Medium Prompt

An example App Engine app using Medium’s [Go SDK](https://github.com/Medium/medium-sdk-go). 

## Prerequisites

+ [The App Engine Go SDK](https://cloud.google.com/appengine/downloads)
+ [ngrok](https://ngrok.com)

## Development

+ Run the local server using `goapp serve`.
+ Run `ngrok http 8080` to create an externally-available tunnel.
+ Head to Medium’s [Applications](https://medium.com/me/applications) page and create a new application.
+ Add `https://<UNIQUE_ID>.ngrok.io/_cb` to the list of callback URLs. **SSL is required.**
+ Head to `https://<UNIQUE_ID>.ngrok.io/admin` and fill in...
  + The Client ID/Secret (provided on the Medium Application detail page).
  + The same callback URL you entered above.
  + A random string used to generate your XSRF token (this only really matters in production).
+ Now visit `https://<UNIQUE_ID>.ngrok.io/`. It should prompt you to log in and, upon success, redirect you to your locally running development instance.

## Deployment

+ Get familiar with [App Engine deployment](https://cloud.google.com/appengine/docs/go/).
+ `goapp deploy`
+ Add the appropriate URL to the callback URLs in your Medium Application settings.
+ Visit `https://<your site>.appspot.com/admin` and enter the relevant settings detailed in the Development steps. Don’t worry, if you check the app.yaml file you’ll see it’s only available to admins of your project.
