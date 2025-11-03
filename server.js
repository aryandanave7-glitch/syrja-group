// server.js
// Helper to normalize keys
function normalizeB64(s){
  if(!s) return s;
  let r = s.replace(/\s+/g,''); // remove all whitespace
  const mod = r.length % 4;
  if(mod > 0) r += '='.repeat(4 - mod);
  return r;
}
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb"); // Import ObjectId

// --- START: MongoDB Setup ---
// IMPORTANT: Use Environment Variable in Production (See Step 4 later)
// For now, paste your connection string here during testing, BUT REMEMBER TO CHANGE IT
const mongoUri = process.env.MONGODB_URI || "mongodb+srv://syrjaServerUser:YOUR_SAVED_PASSWORD@yourclustername.mongodb.net/?retryWrites=true&w=majority"; // Replace placeholder or use env var

if (!mongoUri) {
    console.error("🚨 FATAL ERROR: MONGODB_URI environment variable is not set and no fallback provided.");
    process.exit(1);
}

// Create a MongoClient with options
const mongoClient = new MongoClient(mongoUri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db;
let idsCollection; 
let offlineMessagesCollection; // For 1-on-1 messages
// --- NEW FOR GROUPS ---
let groupsCollection;
let groupOfflineMessagesCollection;
// --- END NEW ---

async function connectToMongo() {
  try {
    await mongoClient.connect();
    db = mongoClient.db("syrjaAppDb");
    
    // --- 1. Syrja IDs Collection ---
    idsCollection = db.collection("syrjaIds");
    await idsCollection.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 });
    
    // --- 2. 1-on-1 Offline Messages Collection ---
    offlineMessagesCollection = db.collection("offlineMessages");
    await offlineMessagesCollection.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 });
    await offlineMessagesCollection.createIndex({ recipientPubKey: 1 });
    await offlineMessagesCollection.createIndex({ senderPubKey: 1 });

    // --- 3. NEW: Groups Collection ---
    groupsCollection = db.collection("groups");
    await groupsCollection.createIndex({ adminPubKey: 1 });
    await groupsCollection.createIndex({ "members.pubKey": 1 }); // Index the pubKey within the members array

    // --- 4. NEW: Group Offline Messages Collection ---
    // This stores messages for offline group members
    groupOfflineMessagesCollection = db.collection("groupOfflineMessages");
    await groupOfflineMessagesCollection.createIndex({ "expireAt": 1 }, { expireAfterSeconds: 0 });
    await groupOfflineMessagesCollection.createIndex({ recipientPubKey: 1 });
    await groupOfflineMessagesCollection.createIndex({ senderPubKey: 1 });
    await groupOfflineMessagesCollection.createIndex({ groupId: 1 });
    
    console.log("✅ Connected successfully to MongoDB Atlas (All collections ready)");
  } catch (err) {
    console.error("❌ Failed to connect to MongoDB Atlas", err);
    process.exit(1);
  }
}
// --- END: MongoDB Setup ---


// Simple word lists for more memorable IDs
const ADJECTIVES = ["alpha", "beta", "gamma", "delta", "zeta", "nova", "comet", "solar", "lunar", "star"];
const NOUNS = ["fox", "wolf", "hawk", "lion", "tiger", "bear", "crane", "iris", "rose", "maple"];

const app = express();

// --- NEW: Explicit CORS Configuration ---
const corsOptions = {
  origin: "*", // Allow all origins (you can restrict this later)
  methods: "GET,POST,DELETE,OPTIONS", // Allow these methods
  allowedHeaders: "Content-Type" // Allow the JSON content type header
};

// Enable pre-flight requests for all routes
app.options('*', cors(corsOptions)); 
// Use the main CORS configuration
app.use(cors(corsOptions));
// --- END NEW ---

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});
// --- START: Syrja ID Directory Service (v2) ---

app.use(express.json()); // Middleware to parse JSON bodies
app.use(cors());       // CORS Middleware

// Initialize node-persist storage


// Endpoint to claim a new Syrja ID
// Endpoint to claim a new Syrja ID (MODIFIED for MongoDB)
app.post("/claim-id", async (req, res) => {
    const { customId, fullInviteCode, persistence, privacy, pubKey } = req.body; // Added privacy

    // Added privacy check in condition
    if (!customId || !fullInviteCode || !persistence || !privacy || !pubKey) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    try {
        // Check if this public key already owns a DIFFERENT ID using MongoDB findOne
        const existingUserEntry = await idsCollection.findOne({ pubKey: pubKey });
        // Use _id from MongoDB document
        if (existingUserEntry && existingUserEntry._id !== customId) {
            return res.status(409).json({ error: "You already own a different ID. Please delete it before claiming a new one." });
        }

        // Check if the requested ID is taken by someone else using MongoDB findOne
        const existingIdEntry = await idsCollection.findOne({ _id: customId });
        if (existingIdEntry && existingIdEntry.pubKey !== pubKey) {
            return res.status(409).json({ error: "ID already taken" });
        }

        // Decode the invite code to extract profile details
        let decodedProfile;
        let statusText = null; // Default to null
        let updateText = null;
        let updateColor = null;
        try {
            decodedProfile = JSON.parse(Buffer.from(fullInviteCode, 'base64').toString('utf8'));
            statusText = decodedProfile.statusText || null; // Extract status text, default to null if missing
            updateText = decodedProfile.updateText || null;
            updateColor = decodedProfile.updateColor || null;
            ecdhPubKey = decodedProfile.ecdhPubKey || null; // <-- NEW
            console.log(`[Claim/Update ID: ${customId}] Decoded Profile - Status Text: '${statusText}'`);
            
        } catch (e) {
            console.error(`[Claim/Update ID: ${customId}] Failed to decode fullInviteCode:`, e);
            // Decide how to handle this - maybe reject the request or proceed without status?
            // For now, we'll proceed with statusText as null.
        }

        // Prepare the document to insert/update for MongoDB
        const syrjaDoc = {
            _id: customId,
            code: fullInviteCode, // Still store raw code for potential fallback/debugging
            pubKey: pubKey,
            permanent: persistence === 'permanent',
            privacy: privacy,
            updatedAt: new Date(),
            // --- NEW: Store extracted fields ---
            name: decodedProfile?.name || null, // Store name
            avatar: decodedProfile?.avatar || null, // Store avatar (URL or null)
            statusText: statusText, // Store status text (string or null)
            ecdhPubKey: ecdhPubKey,
            updateText: updateText,
            updateColor: updateColor,
            updateTimestamp: updateText ? new Date() : null 
            // --- END NEW ---
        };

        // Set expiration only for temporary IDs
        if (persistence === 'temporary') {
            syrjaDoc.expireAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
        } else {
            // Ensure expireAt field is absent or explicitly null for permanent IDs
            // $unset below handles removal if it exists, so no need to set null here if updating.
        }

        // Use replaceOne with upsert:true to insert or replace the document
        await idsCollection.replaceOne(
            { _id: customId },
            syrjaDoc,
            { upsert: true }
        );

        // If making permanent or updating a permanent record, ensure expireAt field is removed
        if (persistence === 'permanent') {
             await idsCollection.updateOne({ _id: customId }, { $unset: { expireAt: "" } });
        }
        // Updated console log
        console.log(`✅ ID Claimed/Updated: ${customId} (Permanent: ${syrjaDoc.permanent}, Privacy: ${privacy})`);
        res.json({ success: true, id: customId });

    } catch (err) {
        console.error("claim-id error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});
// Endpoint to get an invite code from a Syrja ID (for adding contacts)
// Endpoint to get an invite code from a Syrja ID (MODIFIED for MongoDB)
// Endpoint to get an invite code from a Syrja ID (MODIFIED for MongoDB + Block Check)
app.get("/get-invite/:id", async (req, res) => {
    const fullId = `syrja/${req.params.id}`;
    const searcherPubKey = req.query.searcherPubKey; // Get searcher's PubKey from query param

    // --- NEW: Require searcherPubKey ---
    if (!searcherPubKey) {
        return res.status(400).json({ error: "Missing searcherPubKey query parameter" });
    }
    // --- END NEW ---

    try {
        const item = await idsCollection.findOne({ _id: fullId });

        // --- MODIFIED: Check if essential fields exist ---
        if (item && item.pubKey && item.name) {
            // --- Block Check ---
            if (item.blockedSearchers && item.blockedSearchers.includes(searcherPubKey)) {
                console.log(`🚫 Search denied: ${fullId} blocked searcher ${searcherPubKey.slice(0,12)}...`);
                return res.status(404).json({ error: "ID not found" });
            }

            // --- Privacy Check ---
            if (item.privacy === 'private') {
                console.log(`🔒 Attempt to resolve private Syrja ID denied: ${fullId}`);
                return res.status(403).json({ error: "This ID is private" });
            }

            // --- NEW: Reconstruct the invite code payload ---
            const invitePayload = {
                name: item.name,
                key: item.pubKey,
                // Assuming server URL needs to be included - get it from config/env or omit if not needed
                server: process.env.SERVER_URL || '', // Example: Get server URL if needed
                avatar: item.avatar || null,
                statusText: item.statusText || null, // Include status text
                ecdhPubKey: item.ecdhPubKey || null, // <-- NEW
                updateText: item.updateText || null,
                updateColor: item.updateColor || null,
                updateTimestamp: item.updateTimestamp || null
                
            };
            // Remove null/undefined values to keep payload clean
            Object.keys(invitePayload).forEach(key => invitePayload[key] == null && delete invitePayload[key]);

            const reconstructedInviteCode = Buffer.from(JSON.stringify(invitePayload)).toString('base64');
            // --- END NEW ---

            console.log(`➡️ Resolved Syrja ID: ${fullId} (Privacy: ${item.privacy || 'public'}, Status: '${invitePayload.statusText || ''}', Update: '${invitePayload.updateText || ''}')`);
            // --- MODIFIED: Send reconstructed code ---
            res.json({ fullInviteCode: reconstructedInviteCode });
        } else {
            console.log(`❓ Failed to resolve Syrja ID (not found, expired, or missing data): ${fullId}`);
            res.status(404).json({ error: "ID not found, has expired, or profile data incomplete" });
        }
    } catch (err) {
        console.error("get-invite error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});

// Endpoint to find a user's current ID by their public key
// Endpoint to find a user's current ID by their public key (MODIFIED for MongoDB)
app.get("/get-id-by-pubkey/:pubkey", async (req, res) => {
    const pubkey = req.params.pubkey;
    try {
        // Use findOne to search by the pubKey field
        const item = await idsCollection.findOne({ pubKey: pubkey });

        if (item) {
            // Found a match, return the document's _id and other details
            console.log(`🔎 Found ID for pubkey ${pubkey.slice(0,12)}... -> ${item._id}`);
            // Include privacy in the response
            res.json({ id: item._id, permanent: item.permanent, privacy: item.privacy });
        } else {
            // No document found matching the public key
            console.log(`🔎 No ID found for pubkey ${pubkey.slice(0,12)}...`);
            res.status(404).json({ error: "No ID found for this public key" });
        }
    } catch (err) {
        // Handle potential database errors
        console.error("get-id-by-pubkey error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});
// Endpoint to delete an ID, authenticated by public key
// Endpoint to delete an ID, authenticated by public key (MODIFIED for MongoDB)
app.post("/delete-id", async (req, res) => {
    const { pubKey } = req.body;
    if (!pubKey) return res.status(400).json({ error: "Public key is required" });

    try {
        // Use deleteOne to remove the document matching the public key
        const result = await idsCollection.deleteOne({ pubKey: pubKey });

        // Check if a document was actually deleted
        if (result.deletedCount > 0) {
            console.log(`🗑️ Deleted Syrja ID for pubKey: ${pubKey.slice(0,12)}...`);
            res.json({ success: true });
        } else {
            // If deletedCount is 0, no document matched the pubKey
            console.log(`🗑️ No Syrja ID found for pubKey ${pubKey.slice(0,12)}... to delete.`);
            res.json({ success: true, message: "No ID found to delete" });
        }
    } catch (err) {
        // Handle potential database errors
        console.error("delete-id error:", err);
        res.status(500).json({ error: "Database operation failed" });
    }
});

// Endpoint to block a user from searching for you
app.post("/block-user", async (req, res) => {
    const { blockerPubKey, targetIdentifier } = req.body;

    if (!blockerPubKey || !targetIdentifier) {
        return res.status(400).json({ error: "Missing required fields (blockerPubKey, targetIdentifier)" });
    }

    // --- Resolve targetIdentifier to targetPubKey ---
    // This is a simplified resolution. You might need more robust logic
    // depending on whether the client sends an ID or PubKey.
    // Let's assume for now the client resolves and sends the target's PubKey.
    const targetPubKey = targetIdentifier; // Assuming client sends resolved PubKey for simplicity here.
    // TODO: Add logic here if you need the server to resolve a syrja/ ID to a PubKey.
    // ---

    try {
        const blockerDoc = await idsCollection.findOne({ pubKey: blockerPubKey });

        if (!blockerDoc) {
            return res.status(404).json({ error: "Your Syrja ID profile not found." });
        }

        // Use $addToSet to add the targetPubKey to the blocker's blockedSearchers array
        // $addToSet automatically handles duplicates.
        const updateResult = await idsCollection.updateOne(
            { pubKey: blockerPubKey },
            { $addToSet: { blockedSearchers: targetPubKey } }
        );

        if (updateResult.modifiedCount > 0 || updateResult.matchedCount > 0) {
             console.log(`🛡️ User ${blockerPubKey.slice(0,12)}... blocked ${targetPubKey.slice(0,12)}... from searching.`);
             res.json({ success: true, message: "User blocked successfully." });
        } else {
             // This case should ideally not happen if the blockerDoc was found,
             // but included for completeness.
             res.status(404).json({ error: "Could not find your profile to update." });
        }

    } catch (err) {
        console.error("block-user error:", err);
        res.status(500).json({ error: "Database operation failed during block." });
    }
});

// Endpoint to unblock a user, allowing them to search for you again
app.post("/unblock-user", async (req, res) => {
    const { unblockerPubKey, targetIdentifier } = req.body;

    if (!unblockerPubKey || !targetIdentifier) {
        return res.status(400).json({ error: "Missing required fields (unblockerPubKey, targetIdentifier)" });
    }

    // --- Resolve targetIdentifier to targetPubKey ---
    // Assuming client sends resolved PubKey for simplicity here.
    const targetPubKey = targetIdentifier;
    // TODO: Add server-side resolution if needed.
    // ---

    try {
        const unblockerDoc = await idsCollection.findOne({ pubKey: unblockerPubKey });

        if (!unblockerDoc) {
            return res.status(404).json({ error: "Your Syrja ID profile not found." });
        }

        // Use $pull to remove the targetPubKey from the blockedSearchers array
        const updateResult = await idsCollection.updateOne(
            { pubKey: unblockerPubKey },
            { $pull: { blockedSearchers: targetPubKey } }
        );

        // Check if modification happened or if the document was matched
        if (updateResult.modifiedCount > 0) {
            console.log(`🔓 User ${unblockerPubKey.slice(0,12)}... unblocked ${targetPubKey.slice(0,12)}...`);
            res.json({ success: true, message: "User unblocked successfully." });
        } else if (updateResult.matchedCount > 0) {
            // Matched but didn't modify (target wasn't in the array)
            res.json({ success: true, message: "User was not in the block list." });
        }
         else {
            res.status(404).json({ error: "Could not find your profile to update." });
        }

    } catch (err) {
        console.error("unblock-user error:", err);
        res.status(500).json({ error: "Database operation failed during unblock." });
    }
});

// --- MODIFIED: Endpoint to delete ALL relayed messages for a user ---
app.post("/delete-all-relayed-messages", async (req, res) => {
    const { pubKey } = req.body;
    if (!pubKey) {
        return res.status(400).json({ error: "Public key is required." });
    }
    try {
        // --- MODIFIED: Delete from BOTH collections ---
        const p2pDeleteResult = await offlineMessagesCollection.deleteMany({ senderPubKey: pubKey });
        const groupDeleteResult = await groupOfflineMessagesCollection.deleteMany({ senderPubKey: pubKey });
        
        const totalDeleted = p2pDeleteResult.deletedCount + groupDeleteResult.deletedCount;
        console.log(`🗑️ DELETED ALL RELAYED MESSAGES for ${pubKey.slice(0,10)}...`);
        console.log(`   - 1-on-1 messages deleted: ${p2pDeleteResult.deletedCount}`);
        console.log(`   - Group messages deleted: ${groupDeleteResult.deletedCount}`);
        
        res.json({ success: true, messagesDeleted: totalDeleted });
    } catch (err) { console.error("delete-all-relayed-messages error:", err); res.status(500).json({ error: "Database operation failed." }); }
});

// --- MODIFIED: Endpoint to delete all user data from the server ---
app.post("/discontinue-service", async (req, res) => {
    const { pubKey } = req.body;
    if (!pubKey) {
        return res.status(400).json({ error: "Public key is required." });
    }
    try {
        // 1. Delete Syrja ID
        const idDeleteResult = await idsCollection.deleteOne({ pubKey: pubKey });
        
        // 2. Delete all relayed messages (1-on-1 and Group)
        const p2pDeleteResult = await offlineMessagesCollection.deleteMany({ senderPubKey: pubKey });
        const groupDeleteResult = await groupOfflineMessagesCollection.deleteMany({ senderPubKey: pubKey });
        const totalDeleted = p2pDeleteResult.deletedCount + groupDeleteResult.deletedCount;

        // 3. NEW: Remove user from all groups
        const groupUpdateResult = await groupsCollection.updateMany(
            { "members.pubKey": pubKey },
            { $pull: { members: { pubKey: pubKey } } }
        );
        // (Note: This doesn't delete groups where they were the admin, just removes them)
        
        console.log(`🗑️ DISCONTINUE SERVICE for ${pubKey.slice(0,10)}...`);
        console.log(`   - Syrja ID deleted: ${idDeleteResult.deletedCount}`);
        console.log(`   - Relayed messages deleted: ${totalDeleted}`);
        console.log(`   - Removed from groups: ${groupUpdateResult.modifiedCount}`);
        
        res.json({ 
            success: true, 
            idDeleted: idDeleteResult.deletedCount, 
            messagesDeleted: totalDeleted,
            groupsLeft: groupUpdateResult.modifiedCount
        });
    } catch (err) { console.error("discontinue-service error:", err); res.status(500).json({ error: "Database operation failed." }); }
});

// --- START: Offline Message Relay Service ---
const USER_QUOTA_BYTES = 1 * 1024 * 1024; // 1MB
// --- NEW: Group Quota ---
const GROUP_QUOTA_BYTES = 0.5 * 1024 * 1024; // 0.5MB (Per-user, for groups)

app.post("/relay-message", async (req, res) => {
    const { senderPubKey, recipientPubKey, encryptedPayload } = req.body;

    if (!senderPubKey || !recipientPubKey || !encryptedPayload) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    try {
        // 1. Check payload size (encryptedPayload is base64 string)
        const payloadSizeBytes = Buffer.from(encryptedPayload, 'base64').length;
        if (payloadSizeBytes > USER_QUOTA_BYTES) {
             return res.status(413).json({ error: `Payload (${payloadSizeBytes} bytes) exceeds total user quota (${USER_QUOTA_BYTES} bytes).` });
        }

        // 2. Check user's current quota usage
        // --- MODIFIED: Check quota from BOTH collections ---
        const userMessages1on1 = await offlineMessagesCollection.find({ senderPubKey }).toArray();
        const userMessagesGroup = await groupOfflineMessagesCollection.find({ senderPubKey }).toArray(); // <-- NEW

        let currentUsage1on1 = 0;
        userMessages1on1.forEach(msg => { currentUsage1on1 += msg.sizeBytes || 0; });
        
        let currentUsageGroup = 0; // <-- NEW
        userMessagesGroup.forEach(msg => { currentUsageGroup += msg.sizeBytes || 0; }); // <-- NEW

        // This check is for the 1-on-1 quota
        if (currentUsage1on1 + payloadSizeBytes > USER_QUOTA_BYTES) {
            return res.status(413).json({ error: `1-on-1 quota exceeded. Current: ${currentUsage1on1} bytes. This: ${payloadSizeBytes} bytes. Limit: ${USER_QUOTA_BYTES} bytes.` });
        }
        // --- END MODIFIED ---

        // 3. Store the message
        const messageDoc = {
            senderPubKey,
            recipientPubKey,
            encryptedPayload,
            sizeBytes: payloadSizeBytes,
            createdAt: new Date(),
            expireAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14-day TTL
        };

        const insertResult = await offlineMessagesCollection.insertOne(messageDoc);

        console.log(`📦 Relayed message stored: ${insertResult.insertedId} from ${senderPubKey.slice(0,10)}... to ${recipientPubKey.slice(0,10)}...`);
        res.status(201).json({ success: true, messageId: insertResult.insertedId.toString(), size: payloadSizeBytes });

    } catch (err) {
        console.error("relay-message error:", err);
        res.status(500).json({ error: "Database operation failed." });
    }
});

// Endpoint for sender to view their relayed messages and quota
// Endpoint for sender to view their relayed messages and quota
app.get("/my-relayed-messages/:senderPubKey", async (req, res) => {
    const { senderPubKey } = req.params;
    if (!senderPubKey) return res.status(400).json({ error: "Missing sender public key." });

    try {
        // --- MODIFIED: Get messages from BOTH collections ---
        const messages1on1 = await offlineMessagesCollection.find(
            { senderPubKey },
            { projection: { _id: 1, recipientPubKey: 1, sizeBytes: 1, createdAt: 1 } }
        ).toArray();
        
        const messagesGroup = await groupOfflineMessagesCollection.find(
            { senderPubKey },
            { projection: { _id: 1, recipientPubKey: 1, groupId: 1, sizeBytes: 1, createdAt: 1 } }
        ).toArray();
        // --- END MODIFIED ---

        let currentUsage1on1 = 0;
        const formattedMessages1on1 = messages1on1.map(msg => {
            currentUsage1on1 += msg.sizeBytes;
            return { ...msg, type: 'p2p' }; // Add type
        });
        
        let currentUsageGroup = 0;
        const formattedMessagesGroup = messagesGroup.map(msg => {
            currentUsageGroup += msg.sizeBytes;
            return { ...msg, type: 'group' }; // Add type
        });

        res.json({
            p2p: {
                quotaUsed: currentUsage1on1,
                quotaLimit: USER_QUOTA_BYTES,
                messages: formattedMessages1on1
            },
            group: {
                quotaUsed: currentUsageGroup,
                quotaLimit: GROUP_QUOTA_BYTES,
                messages: formattedMessagesGroup
            }
        });
    } catch (err) {
        console.error("my-relayed-messages error:", err);
        res.status(500).json({ error: "Database operation failed." });
    }
});

// Endpoint for sender to delete a message they relayed
app.delete("/delete-relayed-message/:messageId", async (req, res) => {
    const { messageId } = req.params;
    // --- MODIFIED: Get 'type' from query to know which collection to use ---
    const { senderPubKey } = req.body;
    const { type } = req.query; // e.g., ?type=p2p or ?type=group
    
    if (!senderPubKey) return res.status(400).json({ error: "Missing sender public key for auth." });
    if (!type) return res.status(400).json({ error: "Missing 'type' query parameter." });

    try {
        const _id = new ObjectId(messageId);
        let collectionToUse;

        if (type === 'p2p') {
            collectionToUse = offlineMessagesCollection;
        } else if (type === 'group') {
            collectionToUse = groupOfflineMessagesCollection;
        } else {
            return res.status(400).json({ error: "Invalid 'type' parameter." });
        }

        const deleteResult = await collectionToUse.deleteOne({
            _id: _id,
            senderPubKey: senderPubKey // CRITICAL: Ensure only the sender can delete
        });

        if (deleteResult.deletedCount === 1) {
            console.log(`🗑️ Sender ${senderPubKey.slice(0,10)}... deleted relayed ${type} message ${messageId}`);
            res.json({ success: true });
        } else {
            res.status(404).json({ error: "Message not found or you are not the owner." });
        }
    } catch (err) {
        console.error("delete-relayed-message error:", err);
        res.status(500).json({ error: "Database operation failed or invalid ID." });
    }
});

// --- END: Offline Message Relay Service ---

/* =================================================================
   3. NEW: Group Chat Service
   ================================================================= */

// --- NEW: Endpoint to create a group ---
app.post("/group/create", async (req, res) => {
    const { name, adminPubKey, members } = req.body; // members is an array of pubKeys
    if (!name || !adminPubKey || !members || !Array.isArray(members) || members.length < 2) {
        return res.status(400).json({ error: "Missing required fields or invalid members list." });
    }
    
    // Ensure admin is in the members list
    if (!members.includes(adminPubKey)) {
        members.push(adminPubKey);
    }

    try {
        const groupDoc = {
            name,
            adminPubKey,
            members: members.map(key => ({ pubKey: normalizeB64(key), joinedAt: new Date() })), // <-- MODIFIED
            createdAt: new Date(),
        };
        const result = await groupsCollection.insertOne(groupDoc);
        const newGroupId = result.insertedId.toString();

        console.log(`🏛️ Group created: ${name} (ID: ${newGroupId}) by ${adminPubKey.slice(0,10)}...`);
        res.status(201).json({ success: true, groupId: newGroupId, group: groupDoc });
    } catch (err) {
        console.error("group/create error:", err);
        res.status(500).json({ error: "Database operation failed." });
    }
});

// --- NEW: Endpoint to get all groups for a user ---
app.get("/group/my-groups/:pubKey", async (req, res) => {
    const { pubKey } = req.params;
    if (!pubKey) return res.status(400).json({ error: "Missing public key." });

    try {
        const myGroups = await groupsCollection.find({ "members.pubKey": pubKey }).toArray();
        res.json({ success: true, groups: myGroups });
    } catch (err) {
        console.error("group/my-groups error:", err);
        res.status(500).json({ error: "Database operation failed." });
    }
});

// --- NEW: Endpoint to get group info (for key sharing) ---
app.get("/group/info/:groupId", async (req, res) => {
    const { groupId } = req.params;
    const myPubKey = normalizeB64(req.query.myPubKey);
    
    try {
        const _id = new ObjectId(groupId);
        const group = await groupsCollection.findOne({ _id });
        
        if (!group) return res.status(404).json({ error: "Group not found." });
        
        // Auth: Ensure the user asking is part of the group
        if (!group.members.some(m => m.pubKey === myPubKey)) {
            return res.status(403).json({ error: "You are not a member of this group." });
        }

        res.json({ success: true, group });
    } catch (err) {
        console.error("group/info error:", err);
        res.status(500).json({ error: "Database operation failed or invalid ID." });
    }
});


// --- END: Syrja ID Directory Service (v2) ---
// --- START: Simple Rate Limiting ---
const rateLimit = new Map();
const LIMIT = 20; // Max 20 requests
const TIME_FRAME = 60 * 1000; // per 60 seconds (1 minute)

function isRateLimited(socket) {
  const ip = socket.handshake.address;
  const now = Date.now();
  const record = rateLimit.get(ip);

  if (!record) {
    rateLimit.set(ip, { count: 1, startTime: now });
    return false;
  }

  // If time window has passed, reset
  if (now - record.startTime > TIME_FRAME) {
    rateLimit.set(ip, { count: 1, startTime: now });
    return false;
  }

  // If count exceeds limit, block the request
  if (record.count >= LIMIT) {
    return true;
  }

  // Otherwise, increment count and allow
  record.count++;
  return false;
}
// --- END: Simple Rate Limiting ---

// just to confirm server is alive
app.get("/", (req, res) => {
  res.send("✅ Signaling server is running");
});

// Map a user's permanent pubKey to their temporary socket.id
const userSockets = {};

// Map a pubKey to the list of sockets that are subscribed to it
// { "contact_PubKey": ["subscriber_socket_id_1", "subscriber_socket_id_2"] }
const presenceSubscriptions = {};

// Map a socket.id to the list of pubKeys it is subscribed to (for easy cleanup)
// { "subscriber_socket_id_1": ["contact_PubKey_A", "contact_PubKey_B"] }
const socketSubscriptions = {};

// Helper to normalize keys
function normKey(k){ return (typeof k === 'string') ? k.replace(/\s+/g,'') : k; }

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  // Handle client registration
  socket.on("register", async (pubKey) => { // <-- Made async
    if (isRateLimited(socket)) {
      console.log(`⚠️ Rate limit exceeded for registration by ${socket.handshake.address}`);
      return;
    }
    if (!pubKey) return;
    const key = normKey(pubKey);
    userSockets[key] = socket.id;
    socket.data.pubKey = key; // Store key on socket for later cleanup
    console.log(`🔑 Registered: ${key.slice(0,12)}... -> ${socket.id}`);

    socket.emit('registered', { status: 'ok' });
    
    // --- Presence (Unchanged) ---
    const subscribers = presenceSubscriptions[key];
    if (subscribers && subscribers.length) {
      console.log(`📢 Notifying ${subscribers.length} subscribers that ${key.slice(0,12)}... is online.`);
      subscribers.forEach(subscriberSocketId => {
        io.to(subscriberSocketId).emit("presence-update", { pubKey: key, status: "online" });
      });
    }
    
    // --- NEW: Auto-join group rooms ---
    try {
        const myGroups = await groupsCollection.find({ "members.pubKey": key }).toArray();
        if (myGroups.length > 0) {
            console.log(`🏛️ Client ${key.slice(0,10)}... is joining ${myGroups.length} group rooms.`);
            myGroups.forEach(group => {
                socket.join(group._id.toString());
            });
        }
    } catch (err) {
        console.error(`Error auto-joining group rooms for ${key.slice(0,10)}:`, err);
    }
    // --- END NEW ---
 });
  
    // --- NEW: Check for offline relayed messages ---
    
        // --- END NEW ---
  
  
  // --- MODIFIED: Handle client confirmation of message receipt ---
  socket.on("message-delivered", async (data) => {
      if (!data || !data.id || !data.type) return; // <-- Must have type
      if (!socket.data.pubKey) return;

      try {
          const _id = new ObjectId(data.id);
          let collectionToUse;

          if (data.type === 'p2p') {
              collectionToUse = offlineMessagesCollection;
          } else if (data.type === 'group') {
              collectionToUse = groupOfflineMessagesCollection;
          } else {
              return console.warn(`⚠️ Invalid message-delivered type: ${data.type}`);
          }

          const deleteResult = await collectionToUse.deleteOne({
              _id: _id,
              recipientPubKey: socket.data.pubKey 
          });

          if (deleteResult.deletedCount === 1) {
              console.log(`✅ ${data.type} message ${data.id} delivered to ${socket.data.pubKey.slice(0,10)}... and deleted.`);
          } else {
              console.warn(`⚠️ ${data.type} message ${data.id} delivery confirmation failed (not found, or wrong recipient).`);
          }
      } catch (err) {
           console.error(`Error deleting delivered message ${data.id}:`, err);
      }
  });

    
  // --- MODIFIED: Client "pull" request for offline messages ---
  socket.on("check-for-offline-messages", async () => {
      const key = socket.data.pubKey;
      if (!key) return;

      try {
          // 1. Get 1-on-1 Messages
          const p2pMessages = await offlineMessagesCollection.find({ recipientPubKey: key }).toArray();
          if (p2pMessages.length > 0) {
              console.log(`📬 Client ${key.slice(0,10)}... is pulling ${p2pMessages.length} P2P messages.`);
              p2pMessages.forEach(msg => {
                  socket.emit("offline-message", {
                      id: msg._id.toString(),
                      from: msg.senderPubKey,
                      payload: msg.encryptedPayload,
                      sentAt: msg.createdAt,
                      type: 'p2p' // <-- Add type
                  });
              });
          }
          
          // 2. Get Group Messages
          const groupMessages = await groupOfflineMessagesCollection.find({ recipientPubKey: key }).toArray();
          if (groupMessages.length > 0) {
              console.log(`📬 Client ${key.slice(0,10)}... is pulling ${groupMessages.length} GROUP messages.`);
              groupMessages.forEach(msg => {
                  socket.emit("offline-message", {
                      id: msg._id.toString(),
                      from: msg.senderPubKey, // Sender
                      groupId: msg.groupId, // <-- NEW
                      payload: msg.encryptedPayload,
                      sentAt: msg.createdAt,
                      type: 'group' // <-- Add type
                  });
              });
          }

          if (p2pMessages.length === 0 && groupMessages.length === 0) {
               console.log(`📬 Client ${key.slice(0,10)}... pulled messages, 0 found.`);
          }
      } catch (err) {
          console.error(`Error fetching offline messages for ${key.slice(0,10)}:`, err);
      }
  });

  // --- NEW: Handle Group Message Sending ---
  socket.on("send-group-message", async (data) => {
      const { groupId, senderPubKey, encryptedPayload, sizeBytes } = data;
      if (!groupId || !senderPubKey || !encryptedPayload || !sizeBytes) {
          return console.warn("⚠️ Received invalid 'send-group-message' packet.");
      }

      const key = socket.data.pubKey;
      if (key !== senderPubKey) {
          return console.warn(`⚠️ Socket ID ${socket.id} spoofing senderPubKey ${senderPubKey}!`);
      }

      try {
          // 1. Auth: Check if sender is in the group
          const _id = new ObjectId(groupId);
          const group = await groupsCollection.findOne({ _id });
          if (!group || !group.members.some(m => m.pubKey === senderPubKey)) {
              return console.warn(`⚠️ User ${senderPubKey.slice(0,10)}... NOT in group ${groupId}.`);
          }
          
          // 2. Check group quota
          const userMessagesGroup = await groupOfflineMessagesCollection.find({ senderPubKey }).toArray();
          let currentUsageGroup = 0;
          userMessagesGroup.forEach(msg => { currentUsageGroup += msg.sizeBytes; });
          
          if (currentUsageGroup + sizeBytes > GROUP_QUOTA_BYTES) {
              console.warn(`⚠️ Group quota exceeded for ${senderPubKey.slice(0,10)}...`);
              // TODO: Emit an error back to the sender?
              return;
          }

          // 3. Fan out to ONLINE members (including sender for sync)
          // We send the full packet so clients can identify the sender
          const onlineMembers = group.members
              .filter(m => userSockets[m.pubKey]) // Find who is online
              .map(m => userSockets[m.pubKey]);   // Get their socket IDs
          
          console.log(`🏛️ Relaying group message from ${senderPubKey.slice(0,10)}... to ${onlineMembers.length} online members.`);
          onlineMembers.forEach(socketId => {
              io.to(socketId).emit("receive-group-message", {
                  groupId,
                  senderPubKey,
                  encryptedPayload
              });
          });

          // 4. Store for OFFLINE members
          const offlineMembers = group.members.filter(m => !userSockets[m.pubKey]);
          if (offlineMembers.length > 0) {
              console.log(`   ...and storing for ${offlineMembers.length} offline members.`);
              const messageDocs = offlineMembers.map(member => ({
                  groupId, senderPubKey, encryptedPayload, sizeBytes,
                  recipientPubKey: member.pubKey,
                  createdAt: new Date(),
                  expireAt: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)
              }));
              await groupOfflineMessagesCollection.insertMany(messageDocs);
          }

      } catch (err) {
          console.error(`Error handling send-group-message for ${groupId}:`, err);
      }
  });
  // Handle presence subscription
  socket.on("subscribe-to-presence", (contactPubKeys) => {
    console.log(`📡 Presence subscription from ${socket.id} for ${contactPubKeys.length} contacts.`);
  

    // --- 1. Clean up any previous subscriptions for this socket ---
    const oldSubscriptions = socketSubscriptions[socket.id];
    if (oldSubscriptions && oldSubscriptions.length) {
      oldSubscriptions.forEach(pubKey => {
        if (presenceSubscriptions[pubKey]) {
          presenceSubscriptions[pubKey] = presenceSubscriptions[pubKey].filter(id => id !== socket.id);
          if (presenceSubscriptions[pubKey].length === 0) {
            delete presenceSubscriptions[pubKey];
          }
        }
      });
    }

    // --- 2. Create the new subscriptions ---
    socketSubscriptions[socket.id] = contactPubKeys;
    contactPubKeys.forEach(pubKey => {
      const key = normKey(pubKey);
      if (!presenceSubscriptions[key]) {
        presenceSubscriptions[key] = [];
      }
      presenceSubscriptions[key].push(socket.id);
    });

    // --- 3. Reply with the initial online status of the subscribed contacts ---
    const initialOnlineContacts = contactPubKeys.filter(key => !!userSockets[normKey(key)]);
    socket.emit("presence-initial-status", initialOnlineContacts);
  });

  // Handle direct connection requests
  socket.on("request-connection", async ({ to, from }) => {
    if (isRateLimited(socket)) {
      console.log(`⚠️ Rate limit exceeded for request-connection by ${socket.handshake.address}`);
      return;
    }

    const toKey = normKey(to);
    const fromKey = normKey(from);
    const targetSocketId = userSockets[toKey];

    if (targetSocketId) {
      // --- This is the existing logic for ONLINE users ---
      io.to(targetSocketId).emit("incoming-request", { from: fromKey });
      console.log(`📨 Connection request (online): ${fromKey.slice(0, 12)}... → ${toKey.slice(0, 12)}...`);
    } else {
      // --- NEW LOGIC for OFFLINE users with Sleep Mode ---
     // (Inside the else block for offline users in socket.on("request-connection", ...))
      console.log(`- User ${toKey.slice(0, 12)}... is offline. No push notification configured/sent.`);
// All the 'storage.getItem', 'if (subscription)', and 'webpush' code is removed.
    }
  });

  // Handle connection acceptance
  socket.on("accept-connection", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
      io.to(targetId).emit("connection-accepted", { from: normKey(from) });
      console.log(`✅ Connection accepted: ${from.slice(0, 12)}... → ${to.slice(0, 12)}...`);
    } else {
      console.log(`⚠️ Could not deliver acceptance to ${to.slice(0,12)} (not registered/online)`);
    }
  });

  // server.js - New Code
// -- Video/Voice Call Signaling --
socket.on("call-request", ({ to, from, callType }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("incoming-call", { from: normKey(from), callType });
        console.log(`📞 Call request (${callType}): ${from.slice(0,12)}... → ${to.slice(0,12)}...`);
    }
});

socket.on("call-accepted", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("call-accepted", { from: normKey(from) });
        console.log(`✔️ Call accepted: ${from.slice(0,12)}... → ${to.slice(0,12)}...`);
    }
});

socket.on("call-rejected", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("call-rejected", { from: normKey(from) });
        console.log(`❌ Call rejected: ${from.slice(0,12)}... → ${to.slice(0,12)}...`);
    }
});

socket.on("call-ended", ({ to, from }) => {
    const targetId = userSockets[normKey(to)];
    if (targetId) {
        io.to(targetId).emit("call-ended", { from: normKey(from) });
        console.log(`👋 Call ended: ${from.slice(0,12)}... & ${to.slice(0,12)}...`);
    }
});
// ---------------------------------


  // Room and signaling logic remains the same
  socket.on("join", (room) => {
    socket.join(room);
    console.log(`Client ${socket.id} joined ${room}`);
  });

  // Inside server.js
socket.on("auth", ({ room, payload }) => {
  // Log exactly what's received
  console.log(`[SERVER] Received auth for room ${room} from ${socket.id}. Kind: ${payload?.kind}`); // Added log
  try {
    // Log before attempting to emit
    console.log(`[SERVER] Relaying auth (Kind: ${payload?.kind}) to room ${room}...`); // Added log
    // Use io.to(room) to send to everyone in the room including potentially the sender if needed,
    // or socket.to(room) to send to everyone *except* the sender.
    // For auth handshake, io.to(room) or socket.to(room).emit should both work if both clients joined. Let's stick with socket.to for now.
    socket.to(room).emit("auth", { room, payload });
    console.log(`[SERVER] Successfully emitted auth to room ${room}.`); // Added log
  } catch (error) {
    console.error(`[SERVER] Error emitting auth to room ${room}:`, error); // Added error log
  }
});

// ALSO add logging for the 'signal' handler for WebRTC messages:
socket.on("signal", ({ room, payload }) => {
  console.log(`[SERVER] Received signal for room ${room} from ${socket.id}.`); // Added log
  console.log(`[SERVER] Relaying signal to room ${room}...`); // Added log
  socket.to(room).emit("signal", { room, payload }); // Assuming payload includes 'from' etc needed by client
  console.log(`[SERVER] Successfully emitted signal to room ${room}.`); // Added log
});

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
    const pubKey = socket.data.pubKey;

    if (pubKey) {
      // --- 1. Notify subscribers that this user is now offline ---
      const subscribers = presenceSubscriptions[pubKey];
      if (subscribers && subscribers.length) {
        console.log(`📢 Notifying ${subscribers.length} subscribers that ${pubKey.slice(0,12)}... is offline.`);
        subscribers.forEach(subscriberSocketId => {
          io.to(subscriberSocketId).emit("presence-update", { pubKey: pubKey, status: "offline" });
        });
      }

      // --- 2. Clean up all subscriptions this socket made ---
      const subscriptionsMadeByThisSocket = socketSubscriptions[socket.id];
      if (subscriptionsMadeByThisSocket && subscriptionsMadeByThisSocket.length) {
        subscriptionsMadeByThisSocket.forEach(subscribedToKey => {
          if (presenceSubscriptions[subscribedToKey]) {
            presenceSubscriptions[subscribedToKey] = presenceSubscriptions[subscribedToKey].filter(id => id !== socket.id);
            if (presenceSubscriptions[subscribedToKey].length === 0) {
              delete presenceSubscriptions[subscribedToKey];
            }
          }
        });
      }
      delete socketSubscriptions[socket.id];

      // --- 3. Finally, remove user from the main online list ---
      delete userSockets[pubKey];
      console.log(`🗑️ Unregistered and cleaned up subscriptions for: ${pubKey.slice(0, 12)}...`);
    }
  });
});

const PORT = process.env.PORT || 3000;

// Connect to MongoDB *before* starting the HTTP server
connectToMongo().then(() => {
    server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}).catch(err => {
    console.error("🚨 MongoDB connection failed on startup. Server not started.", err);
});

// --- Add graceful shutdown for MongoDB ---
process.on('SIGINT', async () => {
    console.log("🔌 Shutting down server...");
    await mongoClient.close();
    console.log("🔒 MongoDB connection closed.");
    process.exit(0);
});
