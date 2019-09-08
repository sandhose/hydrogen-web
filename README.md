# Brawl

A minimal [Matrix](https://matrix.org/) chat client, focused on performance, offline functionality and working on my Lumia 950 Windows Phone.

## Status

Brawl can currently log you in, or pick an existing session, sync already joined rooms, fill gaps in the timeline, and send text messages. Everything is stored locally.

![Showing multiple sessions, and sending messages](https://bwindels.github.io/brawl-chat/images/brawl-sending.gif)

## Why

I started writing Brawl both to have a functional matrix client on my aging phone, and to play around with some ideas I had how to use indexeddb optimally in a matrix client.

For every interaction or network response (syncing, filling a gap), Brawl starts a transaction in indexedb, and only commits it once everything went well. This helps to keep your storage always in a consistent state. As little data is kept in memory as well, and while scrolling in the above GIF, everything is loaded straight from the storage.

If you find this interesting, feel free to reach me at `@bwindels:matrix.org`.

# How to use

I haven't made a deployment script yet for this, so for now you need to locally `yarn start` or `npm start` and point your browser to `http://localhost:3000`.
