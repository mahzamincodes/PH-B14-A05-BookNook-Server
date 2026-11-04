import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import "dotenv/config";
import multer from "multer";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const PORT = process.env.PORT || 5000;

// Environment validation
const AUTH_URL = process.env.BETTER_AUTH_URL;

if (!AUTH_URL) {
    throw new Error("BETTER_AUTH_URL is missing from environment variables");
}

if (!process.env.DB_USER || !process.env.DB_PASS) {
    throw new Error("MongoDB credentials are missing from environment variables");
}

const allowedOrigins = process.env.CLIENT_URL
    ? process.env.CLIENT_URL.split(",").map((url) => url.trim())
    : ["http://localhost:3000"];

// Middleware
app.use(
    cors({
        origin: (origin, callback) => {
            // Allow requests without an Origin header, such as Postman.
            if (!origin || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(new Error("Not allowed by CORS"));
        },
    }),
);

app.use(express.json());

// Better Auth JWT verification
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
    `mongodb+srv://${encodeURIComponent(process.env.DB_USER)}:${encodeURIComponent(process.env.DB_PASS)}@cluster0.vznqwwk.mongodb.net/`,
);

await client.connect();

console.log("You successfully connected to MongoDB!");

const db = client.db("booknook");
const books = db.collection("books");
const borrows = db.collection("borrows");

// Prevent duplicate borrowing by the same user
await borrows.createIndex(
    { bookId: 1, borrowerEmail: 1 },
    { unique: true },
);

// Custom error helper
const createError = (message, statusCode = 400) => {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
};

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

            if (!process.env.IMGBB_API_KEY) {
                return res.status(500).send({
                    message: "Image upload service is not configured",
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
            console.error("Image upload error:", error);

            res.status(500).send({
                message: "Failed to upload image",
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
            cursor.limit(Math.min(limit, 100));
        }

        const allBooks = await cursor.toArray();

        res.status(200).send(allBooks);
    } catch (error) {
        console.error("Get books error:", error);

        res.status(500).send({
            message: "Failed to get books",
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
        console.error("Get single book error:", error);

        res.status(500).send({
            message: "Failed to get book",
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

        if (
            typeof title !== "string" ||
            !title.trim() ||
            typeof author !== "string" ||
            !author.trim() ||
            typeof category !== "string" ||
            !category.trim() ||
            typeof description !== "string" ||
            !description.trim()
        ) {
            return res.status(400).send({
                message: "Please provide all required fields",
            });
        }

        const allowedCategories = [
            "Fiction",
            "Science",
            "History",
            "Kids",
            "Others",
        ];

        if (!allowedCategories.includes(category)) {
            return res.status(400).send({
                message: "Invalid book category",
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

        if (image !== undefined && typeof image !== "string") {
            return res.status(400).send({
                message: "Invalid image URL",
            });
        }

        const newBook = {
            title: title.trim(),
            author: author.trim(),
            category,
            description: description.trim(),
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
        console.error("Add book error:", error);

        res.status(500).send({
            message: "Failed to add book",
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
            const allowedCategories = [
                "Fiction",
                "Science",
                "History",
                "Kids",
                "Others",
            ];

            if (!allowedCategories.includes(category)) {
                return res.status(400).send({
                    message: "Invalid book category",
                });
            }

            updateFields.category = category;
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
            {
                _id: new ObjectId(id),
                "addedBy.email": req.user.email,
            },
            {
                $set: updateFields,
            },
        );

        if (result.matchedCount === 0) {
            return res.status(404).send({
                message: "Book not found or no longer available",
            });
        }

        res.status(200).send({
            message: "Book updated successfully",
            modifiedCount: result.modifiedCount,
        });
    } catch (error) {
        console.error("Update book error:", error);

        res.status(500).send({
            message: "Failed to update book",
        });
    }
});

// DELETE a book (Only book owner, no active borrows)
app.delete("/books/:id", verifyToken, async (req, res) => {
    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({
                message: "Invalid book ID",
            });
        }

        const bookId = new ObjectId(id);

        const existingBook = await books.findOne({
            _id: bookId,
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

        const activeBorrow = await borrows.findOne({
            bookId: id,
        });

        if (activeBorrow) {
            return res.status(409).send({
                message: "This book cannot be deleted while it has active borrows",
            });
        }

        const result = await books.deleteOne({
            _id: bookId,
            "addedBy.email": req.user.email,
        });

        if (result.deletedCount === 0) {
            return res.status(404).send({
                message: "Book not found",
            });
        }

        res.status(200).send({
            message: "Book deleted successfully",
            deletedCount: result.deletedCount,
        });
    } catch (error) {
        console.error("Delete book error:", error);

        res.status(500).send({
            message: "Failed to delete book",
        });
    }
});

// POST a borrow request (JWT protected)
app.post("/borrows", verifyToken, async (req, res) => {
    const session = client.startSession();

    try {
        const { bookId } = req.body;

        if (!bookId || !ObjectId.isValid(bookId)) {
            return res.status(400).send({
                message: "Please provide a valid book ID",
            });
        }

        const borrowerEmail = req.user.email;
        const bookObjectId = new ObjectId(bookId);

        const borrowedAt = new Date();
        const returnDate = new Date(
            borrowedAt.getTime() + 7 * 24 * 60 * 60 * 1000,
        );

        let insertedId;

        await session.withTransaction(async () => {
            const book = await books.findOne(
                { _id: bookObjectId },
                { session },
            );

            if (!book) {
                throw createError("Book not found", 404);
            }

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

            const updateResult = await books.updateOne(
                {
                    _id: bookObjectId,
                    availableCopies: { $gt: 0 },
                },
                {
                    $inc: { availableCopies: -1 },
                },
                { session },
            );

            if (updateResult.modifiedCount === 0) {
                throw createError(
                    "No copies are currently available",
                    400,
                );
            }

            const borrowResult = await borrows.insertOne(
                borrowRecord,
                { session },
            );

            insertedId = borrowResult.insertedId;
        });

        res.status(201).send({
            message: "Book borrowed successfully",
            insertedId,
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).send({
                message: "You have already borrowed this book",
            });
        }

        if (error.statusCode) {
            return res.status(error.statusCode).send({
                message: error.message,
            });
        }

        console.error("Borrow book error:", error);

        res.status(500).send({
            message: "Failed to borrow book",
        });
    } finally {
        await session.endSession();
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
        console.error("Get borrowed books error:", error);

        res.status(500).send({
            message: "Failed to get borrowed books",
        });
    }
});

// DELETE a borrow record / Return Book (Only borrower)
app.delete("/borrows/:id", verifyToken, async (req, res) => {
    const session = client.startSession();

    try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).send({
                message: "Invalid borrow ID",
            });
        }

        const borrowObjectId = new ObjectId(id);

        await session.withTransaction(async () => {
            const borrowRecord = await borrows.findOne(
                { _id: borrowObjectId },
                { session },
            );

            if (!borrowRecord) {
                throw createError("Borrow record not found", 404);
            }

            if (
                borrowRecord.borrowerEmail?.toLowerCase() !==
                req.user.email
            ) {
                throw createError(
                    "You are not allowed to return this book",
                    403,
                );
            }

            const deleteResult = await borrows.deleteOne(
                {
                    _id: borrowObjectId,
                    borrowerEmail: req.user.email,
                },
                { session },
            );

            if (deleteResult.deletedCount === 0) {
                throw createError("Borrow record not found", 404);
            }

            await books.updateOne(
                {
                    _id: new ObjectId(borrowRecord.bookId),
                },
                {
                    $inc: { availableCopies: 1 },
                },
                { session },
            );
        });

        res.status(200).send({
            message: "Book returned successfully",
        });
    } catch (error) {
        if (error.statusCode) {
            return res.status(error.statusCode).send({
                message: error.message,
            });
        }

        console.error("Return book error:", error);

        res.status(500).send({
            message: "Failed to return book",
        });
    } finally {
        await session.endSession();
    }
});

// Multer and general error handling
app.use((error, req, res, next) => {
    console.error("Server error:", error);

    if (error instanceof multer.MulterError) {
        return res.status(400).send({
            message:
                error.code === "LIMIT_FILE_SIZE"
                    ? "Image size cannot exceed 5MB"
                    : "Image upload error",
        });
    }

    if (error.message === "Only image files are allowed") {
        return res.status(400).send({
            message: error.message,
        });
    }

    if (error.message === "Not allowed by CORS") {
        return res.status(403).send({
            message: "Origin not allowed",
        });
    }

    res.status(500).send({
        message: "Something went wrong on the server",
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Simple CRUD server is running on port ${PORT}`);
});

export default app