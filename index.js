import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import multer from "multer";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Better Auth JWT verification
const AUTH_URL = process.env.BETTER_AUTH_URL;

const JWKS = createRemoteJWKSet(
    new URL("/api/auth/jwks", AUTH_URL),
);

const verifyToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith("Bearer ")) {
            return res.status(401).send({
                message: "Unauthorized access. Token is missing.",
            });
        }

        const token = authHeader.split(" ")[1];

        const { payload } = await jwtVerify(token, JWKS, {
            issuer: AUTH_URL,
            audience: AUTH_URL,
        });

        if (!payload.email || !payload.sub) {
            return res.status(401).send({
                message: "Invalid user information in token.",
            });
        }

        req.user = {
            id: payload.sub,
            email: payload.email.toLowerCase(),
            name: payload.name || "",
        };

        next();
    } catch (error) {
        return res.status(401).send({
            message: "Unauthorized access. Invalid or expired token.",
        });
    }
};

// Multer image upload configuration
const storage = multer.memoryStorage();

const upload = multer({
    storage,
    limits: {
        fileSize: 5 * 1024 * 1024,
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith("image/")) {
            cb(null, true);
        } else {
            cb(new Error("Only image files are allowed"));
        }
    },
});

// MongoDB connection
const client = new MongoClient(
    `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.vznqwwk.mongodb.net/`,
);

async function connectToMongoDB() {
    try {
        await client.connect();
        console.log("You successfully connected to MongoDB!");
        return client;
    } catch (error) {
        console.error("MongoDB connection failed:", error);
        throw error;
    }
}

const connectedClient = await connectToMongoDB();

const db = connectedClient.db("booknook");
const books = db.collection("books");
const borrows = db.collection("borrows");

// Prevent duplicate borrowing by the same user
await borrows.createIndex(
    { bookId: 1, borrowerEmail: 1 },
    { unique: true },
);

// Root route
app.get("/", (req, res) => {
    res.send("Simple CRUD server is running...");
});

// Upload book image (JWT protected)
app.post(
    "/upload-image",
    verifyToken,
    upload.single("image"),
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).send({
                    message: "Please select an image",
                });
            }

            const imageBase64 = req.file.buffer.toString("base64");

            const formData = new FormData();
            formData.append("image", imageBase64);

            const response = await fetch(
                `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
                {
                    method: "POST",
                    body: formData,
                },
            );

            const result = await response.json();

            if (!response.ok || !result.success) {
                return res.status(500).send({
                    message: "Image upload failed",
                });
            }

            res.status(200).send({
                message: "Image uploaded successfully",
                imageUrl: result.data.url,
            });
        } catch (error) {
            res.status(500).send({
                message: "Failed to upload image",
                error: error.message,
            });
        }
    },
);

// GET all books (Public)
app.get("/books", async (req, res) => {
    try {
        const limit = Number(req.query.limit);
        const category = req.query.category;

        const filter = category ? { category } : {};

        const cursor = books.find(filter).sort({
            createdAt: -1,
        });

        if (Number.isInteger(limit) && limit > 0) {
            cursor.limit(limit);
        }

        const allBooks = await cursor.toArray();

        res.status(200).send(allBooks);
    } catch (error) {
        res.status(500).send({
            message: "Failed to get books",
            error: error.message,
        });
    }
});

// GET a single book (JWT protected)
app.get("/books/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({
                message: "Invalid book ID",
            });
        }

        const book = await books.findOne({
            _id: new ObjectId(id),
        });

        if (!book) {
            return res.status(404).send({
                message: "Book not found",
            });
        }

        res.status(200).send(book);
    } catch (error) {
        res.status(500).send({
            message: "Failed to get book",
            error: error.message,
        });
    }
});

// POST a new book (JWT protected)
app.post("/books", verifyToken, async (req, res) => {
    try {
        const {
            title,
            author,
            category,
            description,
            totalCopies,
            image,
        } = req.body;

        if (!title || !author || !category || !description) {
            return res.status(400).send({
                message: "Please provide all required fields",
            });
        }

        const copies = Number(totalCopies);

        if (
            !Number.isInteger(copies) ||
            copies < 1 ||
            copies > 99
        ) {
            return res.status(400).send({
                message: "Total copies must be between 1 and 99",
            });
        }

        const newBook = {
            title: title.trim(),
            author: author.trim(),
            category,
            description,
            totalCopies: copies,
            availableCopies: copies,
            image: image || "",
            addedBy: {
                name: req.user.name,
                email: req.user.email,
            },
            createdAt: new Date(),
        };

        const result = await books.insertOne(newBook);

        res.status(201).send({
            message: "Book added successfully",
            insertedId: result.insertedId,
        });
    } catch (error) {
        res.status(500).send({
            message: "Failed to add book",
            error: error.message,
        });
    }
});

// PATCH a book (Only book owner)
app.patch("/books/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({
                message: "Invalid book ID",
            });
        }

        const existingBook = await books.findOne({
            _id: new ObjectId(id),
        });

        if (!existingBook) {
            return res.status(404).send({
                message: "Book not found",
            });
        }

        if (
            existingBook.addedBy?.email?.toLowerCase() !==
            req.user.email
        ) {
            return res.status(403).send({
                message: "You are not allowed to update this book",
            });
        }

        const {
            title,
            author,
            category,
            description,
            totalCopies,
            image,
        } = req.body;

        const updateFields = {};

        if (title !== undefined) {
            if (typeof title !== "string" || !title.trim()) {
                return res.status(400).send({
                    message: "Book title cannot be empty",
                });
            }
            updateFields.title = title.trim();
        }

        if (author !== undefined) {
            if (typeof author !== "string" || !author.trim()) {
                return res.status(400).send({
                    message: "Author name cannot be empty",
                });
            }
            updateFields.author = author.trim();
        }

        if (category !== undefined) {
            if (typeof category !== "string" || !category.trim()) {
                return res.status(400).send({
                    message: "Category cannot be empty",
                });
            }
            updateFields.category = category.trim();
        }

        if (description !== undefined) {
            if (
                typeof description !== "string" ||
                !description.trim()
            ) {
                return res.status(400).send({
                    message: "Description cannot be empty",
                });
            }
            updateFields.description = description.trim();
        }

        if (image !== undefined) {
            if (typeof image !== "string") {
                return res.status(400).send({
                    message: "Invalid image URL",
                });
            }
            updateFields.image = image;
        }

        if (totalCopies !== undefined) {
            const copies = Number(totalCopies);

            if (
                !Number.isInteger(copies) ||
                copies < 1 ||
                copies > 99
            ) {
                return res.status(400).send({
                    message: "Total copies must be between 1 and 99",
                });
            }

            const borrowedCopies =
                existingBook.totalCopies -
                existingBook.availableCopies;

            if (copies < borrowedCopies) {
                return res.status(400).send({
                    message: `At least ${borrowedCopies} copies are currently borrowed`,
                });
            }

            updateFields.totalCopies = copies;
            updateFields.availableCopies = copies - borrowedCopies;
        }

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({
                message: "No valid fields provided for update",
            });
        }

        updateFields.updatedAt = new Date();

        const result = await books.updateOne(
            { _id: new ObjectId(id) },
            { $set: updateFields },
        );

        res.status(200).send({
            message: "Book updated successfully",
            modifiedCount: result.modifiedCount,
        });
    } catch (error) {
        res.status(500).send({
            message: "Failed to update book",
            error: error.message,
        });
    }
});

// DELETE a book (Only book owner)
app.delete("/books/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({
                message: "Invalid book ID",
            });
        }

        const existingBook = await books.findOne({
            _id: new ObjectId(id),
        });

        if (!existingBook) {
            return res.status(404).send({
                message: "Book not found",
            });
        }

        if (
            existingBook.addedBy?.email?.toLowerCase() !==
            req.user.email
        ) {
            return res.status(403).send({
                message: "You are not allowed to delete this book",
            });
        }

        const result = await books.deleteOne({
            _id: new ObjectId(id),
        });

        res.status(200).send({
            message: "Book deleted successfully",
            deletedCount: result.deletedCount,
        });
    } catch (error) {
        res.status(500).send({
            message: "Failed to delete book",
            error: error.message,
        });
    }
});

// POST a borrow request (JWT protected)
app.post("/borrows", verifyToken, async (req, res) => {
    try {
        const { bookId } = req.body;

        if (!bookId || !ObjectId.isValid(bookId)) {
            return res.status(400).send({
                message: "Please provide a valid book ID",
            });
        }

        const bookObjectId = new ObjectId(bookId);
        const borrowerEmail = req.user.email;

        const book = await books.findOne({
            _id: bookObjectId,
        });

        if (!book) {
            return res.status(404).send({
                message: "Book not found",
            });
        }

        const borrowedAt = new Date();
        const returnDate = new Date(
            borrowedAt.getTime() + 7 * 24 * 60 * 60 * 1000,
        );

        const borrowRecord = {
            bookId,
            title: book.title,
            author: book.author,
            image: book.image || "",
            borrowerName: req.user.name,
            borrowerEmail,
            borrowedAt,
            returnDate,
        };

        let borrowResult;

        try {
            borrowResult = await borrows.insertOne(borrowRecord);
        } catch (error) {
            if (error.code === 11000) {
                return res.status(409).send({
                    message: "You have already borrowed this book",
                });
            }
            throw error;
        }

        const updateResult = await books.updateOne(
            {
                _id: bookObjectId,
                availableCopies: { $gt: 0 },
            },
            {
                $inc: { availableCopies: -1 },
            },
        );

        if (updateResult.modifiedCount === 0) {
            await borrows.deleteOne({
                _id: borrowResult.insertedId,
            });

            return res.status(400).send({
                message: "No copies are currently available",
            });
        }

        res.status(201).send({
            message: "Book borrowed successfully",
            insertedId: borrowResult.insertedId,
        });
    } catch (error) {
        res.status(500).send({
            message: "Failed to borrow book",
            error: error.message,
        });
    }
});

// GET borrowed books (Only logged-in user's records)
app.get("/borrows", verifyToken, async (req, res) => {
    try {
        const borrowedBooks = await borrows
            .find({
                borrowerEmail: req.user.email,
            })
            .sort({ borrowedAt: -1 })
            .toArray();

        res.status(200).send(borrowedBooks);
    } catch (error) {
        res.status(500).send({
            message: "Failed to get borrowed books",
            error: error.message,
        });
    }
});

// DELETE a borrow record / Return Book (Only borrower)
app.delete("/borrows/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({
                message: "Invalid borrow ID",
            });
        }

        const borrowRecord = await borrows.findOne({
            _id: new ObjectId(id),
        });

        if (!borrowRecord) {
            return res.status(404).send({
                message: "Borrow record not found",
            });
        }

        if (
            borrowRecord.borrowerEmail?.toLowerCase() !==
            req.user.email
        ) {
            return res.status(403).send({
                message: "You are not allowed to return this book",
            });
        }

        const deleteResult = await borrows.deleteOne({
            _id: new ObjectId(id),
            borrowerEmail: req.user.email,
        });

        if (deleteResult.deletedCount === 0) {
            return res.status(404).send({
                message: "Borrow record not found",
            });
        }

        await books.updateOne(
            {
                _id: new ObjectId(borrowRecord.bookId),
            },
            {
                $inc: { availableCopies: 1 },
            },
        );

        res.status(200).send({
            message: "Book returned successfully",
        });
    } catch (error) {
        res.status(500).send({
            message: "Failed to return book",
            error: error.message,
        });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Simple CRUD server is running on port ${PORT}`);
});