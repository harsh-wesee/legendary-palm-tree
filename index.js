const express = require("express");
var http = require("http");
const path = require("path");
const cors =  require("cors");
const app = express();
const port = process.env.port || 5000;
var server = http.createServer(app);
var io = require("socket.io")(server, {
    cors:
    {
        origin:"*",
        methods: ['GET', 'POST']
    }
});
const connection = require("./db_connection");
const otpGen = require("otp-generator");

const morgan = require("morgan");
let users = []


var sid = "AC4284069662879f8fcc42508c207347d5";
var auth_token = "b88f97c66a6ce6aa16777eca8f327338";
var twilio = require("twilio")(sid, auth_token);


// middleware
app.use(express.json());
// app.use(cors());

app.get("/users", (req, res) => {
    res.json({ users });
});


const generateOtp = () => {
    return otpGen.generate(6, {
        digits: true,
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false
    });
};

const storeOtpInDB = (phoneNumber, otp) => {
    const insertOtpQuery = "INSERT INTO UserOTPs (mobile_number, otp) VALUES (?, ?)";
    const insertOtpValues = [phoneNumber, otp];

    connection.query(insertOtpQuery, insertOtpValues, (err, result) => {
        if (err) {
            console.error("Error storing OTP in the database:", err);
            return;
        }
        console.log("OTP stored successfully for phone number:", phoneNumber);
    });
};

const sendOtp = (phoneNumber, otp) => {
    return twilio.messages.create({
        from: "+12564484468",
        to: phoneNumber,
        body: `The testing OTP is ${otp}.`
    });
};

const verifyOtpInDB = (socket, phoneNumber, otp) => {
    const query = "SELECT * FROM UserOTPs WHERE mobile_number = ? AND otp = ?"; // Optional: Add timestamp check for OTP validity
    const values = [phoneNumber, otp];
    // console.log("Executing Query:", query);
    // console.log("With Values:", values);


    connection.query(query, values, (err, results) => {
        if (err) {
            console.error("Error verifying OTP:", err);
            socket.emit("otpError", "Failed to verify OTP");
            return;
        }

        if (results.length === 0) {
            socket.emit("otpError", "Invalid OTP or OTP expired");
            return;
        }

        // Check if the user already exists
        const checkUserQuery = "SELECT * FROM Users WHERE mobile_number = ?";
        const checkUserValues = [phoneNumber];
        // console.log("Executing Query:", checkUserQuery);
        // console.log("With Values:", checkUserValues);

        
        
        connection.query(checkUserQuery, checkUserValues, (err, userResults) => {
            if (err) {
                console.error("Error checking user existence:", err);
                socket.emit("otpError", "Failed to check user existence");
                return;
            }
            
            if (userResults.length > 0) {
                socket.emit("otpError", "User already registered");
                return;
            }

            // Add the user to the Users table
            const insertUserQuery = "INSERT INTO Users (mobile_number, username, profile_picture, status, last_seen, is_online) VALUES (?, NULL, NULL, FALSE, NULL, FALSE)";
            const insertUserValues = [phoneNumber];

            connection.query(insertUserQuery, insertUserValues, (err, result) => {
                if (err) {
                    console.error("Error inserting user:", err);
                    socket.emit("otpError", "Failed to create user");
                    return;
                }

                socket.emit("otpSuccess", "User verified and added successfully");

                // Delete OTP after successful verification
                const deleteOtpQuery = "DELETE FROM UserOTPs WHERE mobile_number = ? AND otp = ?";
                connection.query(deleteOtpQuery, values, (err) => {
                    if (err) {
                        console.error("Error deleting OTP record:", err);
                    }
                });
            });
        });
    });
};

const searchNumberInDB = (socket, phoneNumber) => {
    const query = "SELECT * FROM Users WHERE mobile_number LIKE ?";
    const values = [`%${phoneNumber}`];
    console.log("Query: ", query);
    console.log("Values:", values);
    connection.query(query, values, (err, results) => {
        if (err) {
            console.error("Error in finding phone number:", err);
            socket.emit("phone-error", "Failed to find phone number");
            return;
        }
        if (results.length === 0) {
            socket.emit("user-exists-response", { contactNumber: phoneNumber, exists: false });
            return;
        }
        else {
            socket.emit("user-exists-response", { contactNumber: phoneNumber, exists: true });
        }
    });
}

// Image Download Endpoint
app.get('/download/:folder/:filename', (req, res) => {
    const { folder, filename } = req.params;
    console.log("Folder:", folder);
    const filePath = path.join(__dirname, folder, filename);
    res.download(filePath, (err) => {
        if (err) {
            console.error("Error downloading file:", err);
            res.status(500).send("Error downloading file");
        }
    });
});

// Static File Serving
app.use("/images", express.static(path.join(__dirname, 'images')));
app.use("/documents", express.static(path.join(__dirname, 'documents')));
app.use("/audios", express.static(path.join(__dirname, 'audios')));
app.use("/others", express.static(path.join(__dirname, 'others')));





var clients={};
const routes = require("./routes");
const { type } = require("os");
app.use("/", routes);



io.on("connection", (socket) => {
    console.log("connected to socket");
    console.log(socket.id, "has joined");

    socket.on("generateOtp", (phoneNumber) => {
        if (!phoneNumber) {
            socket.emit("otpError", "Phone number is required");
            return;
        }
        const otp = generateOtp();
        console.log("Generated OTP:", otp);
        console.log("Phone Number", phoneNumber);
        sendOtp(phoneNumber, otp)
            .then(() => {
                console.log("Message has been sent successfully!");
                socket.emit("otpSuccess", "OTP sent successfully");
            })
            .catch((error) => {
                console.log(error);
                socket.emit("otpError", "Failed to send OTP");
            });
        storeOtpInDB(phoneNumber, otp);
    });

    socket.on("verifyOtp", (phoneNumber, otp) => {
        console.log(`Received Number: ${phoneNumber} and otp ${otp}`);
        if (!phoneNumber || !otp) {
            socket.emit("otpError", "Phone number and OTP are required");
            return;
        }
        verifyOtpInDB(socket, phoneNumber, otp);
    })

    socket.on("signin", (id)=>{
        console.log(id);
        clients[id] = socket;
        // console.log(clients[id]);
    });

    socket.on("get-contacts", (data) => {
        console.log("Phone Number: ", data.phoneNumber);
        searchNumberInDB(socket, data.phoneNumber);
    });

    socket.on("message", (msg) => {
        console.log("Message Received:", msg);

        let targetId = msg.targetid;
        console.log("target id: ", targetId);
        if(targetId) 
        {
            clients[targetId].emit("message", msg);
        }

        insertMessage(msg);
    });

    // Listen for the user authentication or data setting
    socket.on('set-user', (userData) => {
        // Store user information with the socket ID
        users[socket.id] = userData;
        console.log('User data set for socket', socket.id, ':', userData);
    });

    // When we get a call to start a call
    socket.on("start-call", (data) => {
        socket.join(data.roomId);
        console.log(data.roomId);
        receiver = findSocketIdByUserId(users, data.to);
        // console.log(`Socket ID: ${socket.id}, Initiating call request to ${receiver} and the calltype is ${data.isVideoCall}`);
        // console.log("Current clients:", clients[data.to]);
        caller = findClientIdBySocketId(socket.id, clients);
        console.log(caller);
    
        if (clients[data.to]) {
            console.log(`Emitting incoming-call to ${data.name}`);
            // clients[data.to].emit("incoming-call", { from: socket.id , isVideoCall: data.isVideoCall});
            io.to(receiver).emit("incoming-call", { from: caller, roomId: data.roomId, isVideoCall: data.isVideoCall});
        } else {
            console.log(`Client ${data.to} not found`);
        }
    });


    // When an incoming call is accepted
    socket.on('accept-call', (data) => {
        const user = users[socket.id];
        // console.log("User:", user);
        if (!user) {
            console.error('User data is not set for socket', socket.id);
            return;
        }
        // console.log(data.to);
        const recipientUser = findSocketIdByUserId(users, data.to);
        // console.log("Caller:", recipientUser);
        if (!recipientUser) {
            console.error('Recipient user data is not set for socket', socket.id);
            return;
        }
        console.log(`Call accepted by ${user.name} from ${recipientUser}`);
        console.log("Room Id: ", data.roomId);
        socket.join(data.roomId);
        // console.log(data.to);
        io.to(recipientUser).emit("call-accepted", { roomId: data.roomId, to: data.to, isVideoCall: data.isVideoCall });
    });

    // When an incoming call is denied
    socket.on("reject-call", ({ to }) => {
        console.log("Call rejected by ", socket.user, " from ", to);
        io.to(to).emit("call-denied", { to });
    });

    // When a party leaves the call
    socket.on("leave-call", ({ to }) => {
        console.log("Left call message by ", socket.user, " from ", to);
        io.to(to).emit("left-call", { to });
    });

    // When an incoming call is accepted
    // Caller sends their WebRTC offer
    socket.on("offer-sdp", (data) => {
        // console.log("Users:", users);
        const receiver = findSocketIdByUserId(users, data.to);
        // console.log("Receiver:", receiver);
        console.log("Offer from ", socket.id, " to ", receiver);
        // console.log("SDP Offer:", data.sdp);
        if(receiver) {
            console.log(receiver)
            io.to(receiver).emit("offer", { to: socket.id, sdp: data.sdp, type: data.type });
            console.log("Sent.");
        }
        else {
            console.log("error");
        }
        
        console.log(receiver, 'has got the SDP offer.');
    });

    // When an offer is received
    // Receiver sends a WebRTC offer-answer
    socket.on("answer-sdp", (data) => {
        // console.log("SDP answer: ", data.sdp);
        console.log(data.to);
        console.log("Offer answer from ", socket.id, " to ", data.to);
        io.to(data.to).emit("offer-answer", { to: socket.id, sdp: data.sdp, type: data.type });
    });

    // When an ICE candidate is sent
    socket.on("ice-candidate", (data) => {
        console.log(data.to);
        receiver = findSocketIdByUserId(users, data.to);
        // console.log("Receiver:", receiver);
        console.log("ICE candidate from ", socket.id, " to ", receiver);
        // console.log("ICE candidates: ", data.candidate);
        // console.log("ICE Candidate sent!");
        io.to(receiver).emit("ice-candidate", { to: socket.id, candidate: data.candidate });
    });


    socket.on("ice-candidate-to-caller", (data) => {
        console.log(data.to);
        // console.log("ICE candidate from ", socket.id, " to ", data.to);
        io.to(data.to).emit("ice-candidate-of-receiver", { to: socket.id, candidate: data.candidate });
    })

    // socket.on("ice-candidate-to-caller", (data) => {
    //     console.log("Received");
    // })

    // When a socket disconnects
    socket.on("disconnect", (reason) => {
        users = users.filter((u) => u != socket.user);

        users.forEach((user) => {
            io.to(user).emit("user-left", { user: socket.user });
        });
        console.log("A socket disconnected ", socket.user);
    });
});

function findSocketIdByUserId(users, userId) {
    return Object.keys(users).find(socketId => users[socketId].id === userId);
}

function findClientIdBySocketId(socketId, clients) {
    let foundId = null;

    for (const id in clients) {
        if (clients[id].id === socketId) {  // Check if the stored socket's id matches the socketId
            foundId = id;
            break;
        }
    }

    return foundId
}
  

const insertMessage = (msg) => {
    connection.beginTransaction((err) => {
        if(err) {
            console.error("Transaction error:", err);
            return;
        }

        const checkChatQuery = "SELECT chat_id FROM Chats WHERE (user_one_id = ? AND user_two_id = ?) OR (user_one_id = ? AND user_two_id = ?) LIMIT 1;";
        const checkChatValues = [msg.sourceid, msg.targetid, msg.targetid, msg.sourceid];

        // console.log("Checking for existing chat with query:", checkChatQuery);
        // console.log("Values:", checkChatValues);

        connection.query(checkChatQuery, checkChatValues, (err, results) => {
            if(err) {
                return connection.rollback(() => {
                    console.error("Error checking for existing chat:", err);
                });
            }
            let chatId;

            if(results.length > 0) {
                chatId = results[0].chat_id;
                console.log("Chat already exist. chat_id:", chatId);
                insertMessageEntry(chatId);
            }
            else
            {
                const insertChatQuery = "INSERT INTO Chats (user_one_id, user_two_id, last_message_time) VALUES (?, ?, ?);";
                const insertChatValues = [msg.sourceid, msg.targetid, new Date()];

                // console.log("Inserting new chat with query", insertChatQuery);
                // console.log("Values", insertChatValues);

                connection.query(insertChatQuery, insertChatValues, (err, result) => {
                    if(err) {
                        return connection.rollback(() => {
                            console.error("Error inserting new chat:", err);
                        });
                    }

                    chatId = result.insertId;
                    console.log("New Chat Inserted. chat_id:", chatId);
                    insertMessageEntry(chatId);
                });
            }
        });
    });

    const insertMessageEntry = (chatId) => {
        if(!msg) {
            console.error("No message data available");
            return;
        }

        let messageType = '';
        if(msg.path == '') {
            messageType = 'text';
        }
        else if(msg.path != '') {
            const fileExtension = path.parse(msg.path).ext.toLowerCase();
            console.log(fileExtension);
            if (['.jpg', '.jpeg', '.png', '.gif'].includes(fileExtension)) {
                messageType = 'image';
            // } else if (['mp4', 'mkv', 'mov'].includes(fileExtension)) {
            //     messageType = 'video';
            } else if (['.mp3', '.wav', '.aac'].includes(fileExtension)) {
                messageType = 'audio';
            // } else if (['pdf', 'doc', 'docx', 'xls', 'xlsx'].includes(fileExtension)) {
            //     messageType = 'file';
            } else {
                messageType = 'unknown'; // Fallback for unsupported types
            }
        }
        else {
            messageType = 'unknown';
        }

        const insertMessageQuery = "INSERT INTO Messages (chat_id, sender_id, message_text, media_url, message_type, created_at) VALUES (?, ?, ?, ?, ?, ?)";
        const insertMessageValues = [chatId, msg.sourceid, msg.message, msg.path, messageType, new Date()];

        // console.log("Inseting message with query:", insertMessageQuery);
        // console.log("Values:", insertMessageValues);

        connection.query(insertMessageQuery, insertMessageValues, (err, result) => {
            if(err) {
                return connection.rollback(() => {
                    console.error("Error Inserting Message:", err);
                });
            }

            const messageId = result.insertId;

            const updateChatQuery = "UPDATE Chats SET last_message_id = ?, last_message_time = ? WHERE chat_id = ?";
            const updateChatValues = [messageId, new Date(), chatId];

            // console.log("Updating chat with query:", updateChatQuery);
            // console.log("Values:", updateChatValues);

            connection.query(updateChatQuery, updateChatValues, (err, results) => {
                if(err)
                {
                    return connection.rollback(() => {
                        console.error("Error updating chat with last message_id:", err);
                    });
                }

                insertMessageReceiptEntry(messageId, msg.targetid);

                connection.commit((err) => {
                    if(err) {
                        return connection.rollback(() => {
                            console.error("Transaction commit failed:", err);
                        });
                    }
                    console.log("Message Inserted with Id:", messageId);
                });
            });
        });
    };

    const insertMessageReceiptEntry = (messageId, receiverId) => {
        const insertReceiptQuery = "INSERT INTO MessageReceipts (message_id, user_id, delivered_at, read_at) VALUES (?, ?, ?, NULL)";
        const insertReceiptValues = [messageId, receiverId, new Date()];

        connection.query(insertReceiptQuery, insertReceiptValues, (err, result) => {
            if (err) {
                return connection.rollback(() => {
                    console.error("Error Inserting Message Receipt:", err);
                });
            }

            console.log("Message Receipt Inserted with message_id:", messageId, "and receiver_id:", receiverId);
        });
    };
};


server.listen(port, "0.0.0.0", () => {
    console.log("Server is Started.");
});