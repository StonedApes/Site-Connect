const express = require('express');
     const http = require('http');
     const { Server } = require('socket.io');

     const app = express();
     const server = http.createServer(app);
     const io = new Server(server);

     io.on('connection', (socket) => {
         console.log('A user connected');

         socket.on('message', (msg) => {
             io.emit('message', msg); // Broadcast to all clients
         });

         socket.on('collaborationUpdate', (update) => {
             io.emit('collaborationUpdate', update); // Broadcast collaboration updates
         });

         socket.on('disconnect', () => {
             console.log('A user disconnected');
         });
     });

     server.listen(3000, () => {
         console.log('Server running on http://localhost:3000');
     });