const express = require("express");
const { MongoClient } = require("mongodb");
require("dotenv").config();
const cors = require("cors");
// const bodyParser = require('body-parser');
const ObjectId = require("mongodb").ObjectId;
const firebaseAdmin = require("firebase-admin");
const fileUpload = require("express-fileupload");
const axios = require("axios");
const globals = require("node-global-storage");
const { v4: uuidv4 } = require("uuid");

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://easy-mart-ecommerce-final.netlify.app",
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
// app.use(cors())
// app.use(bodyParser.json())
// or
app.use(express.json());
app.use(fileUpload());

// bkish credential ...................................
// middleware  bkash
const bkashAuth = async (req, res, next) => {
  globals.unset("id_token");
  try {
    const { data } = await axios.post(
      process?.env?.bkash_grant_token_url,
      {
        app_key: process?.env?.bkash_api_key,
        app_secret: process?.env.bkash_secret_key,
      },
      {
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          username: process?.env?.bkash_username,
          password: process?.env?.bkash_password,
        },
      }
    );

    globals.set("id_token", data?.id_token, { protected: true });

    next();
  } catch (error) {
    return res.status(401).send({ error: error?.message });
  }
};

// const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert({
    type: "service_account",
    project_id: "easy-mart-a5f75",
    private_key_id: "335b7047ed38bb5de399a2aa1c87be16ae600faa",
    private_key:
      "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCa+pBLMuqk/6kw\n2vwyGDNhFtmNuXHEsl6jHijF1xEcxVJqVQ6HSEFgXX0FCYcyo2PBe2F++ofvDsiP\ncv5re3YIZZf/Xa+MCqTUBQ8KAgRjQJWxCY3K4+KnnBErPRJVx8r8Ac/7p5x8epEo\n+wkNIkveAQMHW0AkQnZRWuze6S9n9uaS4f3jrZoXQGDnkwWYkWdkxfg0YEJEL5GE\nNqsYtffGB7C43bXnfE1+eYNtwlcEnHvheRCF1Xnzl0bUw4dHTpUrysQRhMe4nzoE\nN5O/QWZtDh3vF2Pqfzxfp6jFEU1ppvN6WCPqo49cY5RhOGKNLEs1Ob4/we0PlcGl\nTTMlnAeHAgMBAAECggEAKOxYFNtVlYtDCHkS1kGIs67+dIuO7KMzFTyeBJvlU2UR\nfa2HIBbm2ITnQeDBuA/oBAvJ82dBZNFRCXwSjZw0z0PQbqi09bRL0Qai8YAV24WO\n4YhFzlj9nUe7SuEeCdOvmHr8ChY43q/Yy+r5+WNgiDdZLuScG9cG+jWZzcTidT+W\nauSFWBBD0y0zp60ZTd3VjbTkpxETOoCR4s485HSLEG+QprMsR1ok5BRRjwELyIdp\n0IbdrxRzdQKCghQNe5ENQFAiC2QYgJTr9UnfXVsqEtLn0jpEa3Ye9tOU7p7jNsjV\nIZFSkx1ehgb/YZK/ITmpSc1mlRxVWfs5w4zl4azHjQKBgQDL+LLAMPkpdSlSiLss\nY2OOt7mmeQDxo/N6CFO9RBNF1mru3Gll1ujWz+5wsTl/xpvRAFrQjeDV2470ms4I\nvvzdt7wllxbJ+0iUOdLTx+wuhWa4emnQgvrn8ghZrX9YUFTNUD4OSkHeRTQyWUt8\n4ZwV91HMM7DG25lI03npfQCFdQKBgQDCgqZZwlT/ThKqRKX/FApu5AbsAjC8IBnT\nT/MOzweqDxyxb+BeUUJucjqp8/ZZWGuDG/vzAGDUNWlv1zUeNMpEcJyvgxL20Fk8\nXYMlrehQPzbAw3TuaEzjBMEQDmEEbAFusik6+s33iy8Yh+1cMSWlgZ49vDsBrK5Y\nuN/kcaYtiwKBgQCovxDLFfkcxlQwdvQ7DeLQsMkDo7oXL6d//yGgRJCZR4HiKTF9\nUmYBSbcfPk+umVZRe7SmM6qd4u4LCYOJEtDKcXZTtwLgiWaLUqdMFGseNbk8x/GA\n0svXVpJ39qSTIKp3zXn5go+p3qEHQn7ESzZBqgHfKaiHbCgNav/CHmtu/QKBgQCe\ntT/KiVgVILz2FSFkqhOBO6myNG9TcNXhp6Bo+uAEEGSXGvP1wVP1DltzhM4DRLQk\nvFathid7v0ESsoRy6xwHD+OpCcgVfxbwvFRgEDA4Gfww+MqWJKBns99bnH/ovb/F\ndLVTnIUmcHizCWXRDYDsNIDLWqTCzwVK+z4kBd9T1QKBgQCKoAstI+rTJq3kDfk+\nR6gkrS9mgU4gtF0MneWgHZIZr2kjlXr958F1OsYtXHzdk2eQM2jnt0DXtEpWD2ko\nHOnKa62nf+doKWfP6JNzLGivjiyg9zpKAMqL3nkIBS6iqgwZBiH8Agu0m+yLFbxb\nhPVV8NeK5Dk0FCT0x3eRuVqKFg==\n-----END PRIVATE KEY-----\n",
    client_email:
      "firebase-adminsdk-t911q@easy-mart-a5f75.iam.gserviceaccount.com",
    client_id: "105725313191903383703",
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
    client_x509_cert_url:
      "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-t911q%40easy-mart-a5f75.iam.gserviceaccount.com",
    universe_domain: "googleapis.com",
  }),
});
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.044ysfk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

async function verifyToken(req, res, next) {
  try {
    if (req.headers?.authorization?.startsWith("Bearer ")) {
      const token = req.headers.authorization.split(" ")[1];
      // console.log("token: " + token);
      const decodedUser = await admin.auth().verifyIdToken(token);
      // console.log("decodedUser: " + decodedUser);
      // Attach the decoded email to the request object
      // console.log(req.decodedEmail);
      // console.log(decodedUser.email);
      // console.log(req.decodedEmail = decodedUser.email);
    } else {
      // Respond with error if no token is provided
      return res.status(401).json({ error: "Unauthorized: No token provided" });
    }
  } catch (error) {
    console.error("Token verification failed:", error.message);
    // Respond with an unauthorized error if token verification fails
    return res
      .status(401)
      .json({ error: "Unauthorized: Invalid or expired token" });
  }

  next();
}

async function run() {
  try {
    // await client.connect();
    const database = client.db("easy_mart");
    const productCollection = database.collection("products");
    const categoriesCollection = database.collection("categories");
    const brandsCollection = database.collection("brands");
    const vendorsCollection = database.collection("vendors");
    const ordersCollection = database.collection("orders");
    const ordersPaymentMethodCollection = database.collection(
      "ordersPaymentMethod"
    );
    const usersCollection = database.collection("users");
    const messageCollection = database.collection("messages");
    const couponCollection = database.collection("coupon");

    // ---------------------------------------------------------
    // ------------------- productCollection  -------------------
    // ----------------------------------------------------------
    // get all the products method
    app.get("/products", async (req, res) => {
      const cursor = productCollection.find({});
      const result = await cursor.toArray();
      res.send(result);
    });

    // New added products
    app.put("/product/add/:cate_name", async (req, res) => {
      const cateName = req.params.cate_name;
      const products = req.body;
      const filter = { cate_name: cateName };
      const updateDoc = { $push: { products: products } };
      const result = await productCollection.updateOne(filter, updateDoc);
      res.json(result);
    });

    // query = {"user_id" : "{1231mjnD-32JIjn-3213}", "campaigns.campaign_id": 3221}
    // message = {"message_id":4213122, "email":"john@gmail.com"}
    // op = {"$push" : {"campaigns.messages":message}}
    // mongo.TestDatabase.members.update(query, op)

    // products update
    // http://localhost:5000/users?search=tamal&&order=asc
    // const search = req.query.search;
    app.put("/product/edit/:cate_name/:id", async (req, res) => {
      const category = req.params.cate_name;
      const id = req.params.id;
      const product = req.body;
      const filter = { cate_name: category, "products._id": id };
      const updateDoc = { $set: { "products.$": product } };
      const result = await productCollection.updateOne(filter, updateDoc);
      res.json(result);
    });

    // products delete
    app.put("/product/delete/:cate_name/:id", async (req, res) => {
      const category = req.params.cate_name;
      const id = req.params.id;
      const filter = { cate_name: category, "products._id": id };
      const updateDoc = { $pull: { products: { _id: id } } };
      const result = await productCollection.updateOne(filter, updateDoc);
      res.json(result);

      console.log(result);
    });
    // ---------------------------------------------------------
    // ------------------- categoriesCollection  -------------------
    // ----------------------------------------------------------
    app.get("/categories", async (req, res) => {
      const cursor = categoriesCollection.find({});
      const result = await cursor.toArray();
      res.send(result);
    });

    app.post("/categories", async (req, res) => {
      const category = req.body;
      const addCategories = {
        name: category.name,
        subCategories: [],
        logo_url: category.logo_url,
      };
      const result = await categoriesCollection.insertOne(addCategories);
      res.json(result);
    });

    app.delete("/categories/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const user = await categoriesCollection.deleteOne(query);
      res.json(user);
    });
    // ---------------------------------------------------------
    // ------------------- brandsCollection  -------------------
    // ----------------------------------------------------------
    app.get("/brands", async (req, res) => {
      const cursor = brandsCollection.find({});
      const result = await cursor.toArray();
      res.send(result);
    });

    app.post("/brands", async (req, res) => {
      const brand = req.body;
      const addBrand = {
        name: brand.name,
        logo_url: brand.logo_url,
      };
      const result = await brandsCollection.insertOne(addBrand);
      res.json(result);
    });

    app.delete("/brands/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const user = await brandsCollection.deleteOne(query);
      res.json(user);
    });

    // ---------------------------------------------------------
    // ------------------- vendorsCollection  -------------------
    // ----------------------------------------------------------
    app.get("/vendors", async (req, res) => {
      const cursor = vendorsCollection.find({});
      const result = await cursor.toArray();
      res.send(result);
    });

    app.post("/vendors", async (req, res) => {
      const vendor = req.body;
      const addVendor = {
        name: vendor.name,
        email: vendor.email,
        phone: vendor.phone,
        website: vendor.website,
        address: vendor.address,
        status: vendor.status,
        logo_url: vendor.logo_url,
        phone: vendor.phone,
      };
      const result = await vendorsCollection.insertOne(addVendor);
      res.json(result);
    });

    app.delete("/vendors/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const user = await vendorsCollection.deleteOne(query);
      res.json(user);
    });

    // ---------------------------------------------------------
    // ------------------- usersCollection  -------------------
    // ----------------------------------------------------------

    app.get("/users", async (req, res) => {
      const cursor = usersCollection.find({});
      const result = await cursor.toArray();
      res.send(result);
    });
    //  Add method
    app.post("/users", async (req, res) => {
      const user = req.body;
      const result = await usersCollection.insertOne(user);
      console.log(result);
      res.json(result);
    });
    // Delete method
    app.delete("/users/:id", async (req, res) => {
      const id = req.params.id;

      try {
        const query = { _id: new ObjectId(id) };

        const userToDelete = await usersCollection.findOne(query);
        if (!userToDelete) {
          return res.status(404).json({ message: "User not found." });
        }

        if (userToDelete.role === "admin") {
          return res
            .status(403)
            .json({ message: "Cannot delete an admin user." });
        }

        const result = await usersCollection.deleteOne(query);

        res.status(200).json(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "An error occurred." });
      }
    });

    app.put("/users", async (req, res) => {
      const user = req.body;
      const filter = { email: user.email };
      const options = { upsert: true };
      const updateDoc = { $set: user };
      const result = await usersCollection.updateOne(
        filter,
        updateDoc,
        options
      );
      console.log(result);
      res.json(result);
    });
    // update method
    app.put("/users/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const updateUser = req.body;
      const updateDoc = {
        $set: {
          displayName: updateUser.displayName,
          email: updateUser.email,
          phoneNumber: updateUser.phoneNumber,
          address: updateUser.address,
          vendor: updateUser.vendor,
          vendors_name: updateUser.vendors_name,
        },
      };
      const result = await usersCollection.updateOne(query, updateDoc);
      res.json(result);
    });

    // app.put('/users/:id', async (req, res) => {
    //     const id = req.params.id;
    //     const role = req.body;
    //     const filter = { _id: ObjectId(id) };
    //     const updateDoc = {
    //         $set: {
    //           role: role
    //         }
    //     };
    //     const result = await usersCollection.updateOne(filter, updateDoc);
    //     res.json(result);
    // })

    app.put("/users/admin/makeAdmin", async (req, res) => {
      try {
        const { currentUser, email } = req.body;

        if (!email) {
          return res.status(400).json({ message: "Email is required" });
        }

        // Check if the requester is an admin
        const requesterAccount = await usersCollection.findOne({
          email: currentUser,
        });
        if (!requesterAccount || requesterAccount.role !== "admin") {
          return res
            .status(403)
            .json({ message: "You do not have permission to make admin" });
        }

        // Update the user's role to admin
        const filter = { email };
        const updateDoc = { $set: { role: "admin" } };
        const result = await usersCollection.updateOne(filter, updateDoc);

        res.status(200).json(result);
      } catch (error) {
        console.error("Error in /users/admin:", error);
        res.status(500).json({ message: "Internal server error", error });
      }
    });
    app.delete("/removeAdmin/:id", async (req, res) => {
      const adminId = req.params.id;

      try {
        const query = { _id: new ObjectId(adminId) };
        const result = await usersCollection.deleteOne(query);
        res.status(200).json(result);
      } catch (error) {
        console.error(error);
        res.status(500).json({ message: "An error occurred." });
      }
    });

    app.get("/users/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      let isAdmin = false;
      if (user?.role === "admin") {
        isAdmin = true;
      }
      res.json({ admin: isAdmin });
    });

    // ---------------------------------------------------------
    // ------------------- ordersCollection  -------------------
    // ----------------------------------------------------------
    // //GET API Orders
    app.get("/orders", async (req, res) => {
      const cursor = ordersCollection.find({});
      const result = await cursor.toArray();
      res.json(result);
    });

    app.post("/orders", async (req, res) => {
      const order = req.body;
      try {
        const session = client.startSession();
        session.startTransaction();

        for (const orderedProduct of order.products) {
          const productId = orderedProduct.prod_id;
          const quantity = orderedProduct.prod_quantity;

          // Decrease stock
          await productCollection.updateOne(
            { "products._id": productId },
            { $inc: { "products.$[elem].stock": -quantity } },
            {
              arrayFilters: [{ "elem._id": productId }],
              session,
            }
          );
        }
        // Insert the order into the orders collection
        const orderResult = await ordersCollection.insertOne(order, {
          session,
        });
        // Commit transaction
        await session.commitTransaction();
        session.endSession();
        res.status(201).json(orderResult);
      } catch (error) {
        console.error("Error processing order:", error);
        res.status(500).json({
          message: "An error occurred while processing the order.",
          error: error.message,
        });
      }
    });

    // // GET API Orders Id
    // app.get('/orders/:email', async (req, res) => {
    //   const email = req.params.email;
    //   const query = { receiver_email: email };
    //   const order = await ordersCollection.findOne(query);
    //   console.log("query", order)
    //   res.send(order);
    // })

    app.put("/orders/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const order_status = req.body.order_status;
      const options = { upsert: true };
      const updateDoc = {
        $set: { order_status: order_status },
      };
      const result = await ordersCollection.updateOne(
        query,
        updateDoc,
        options
      );
      res.json(result);
    });

    // Delete API Orders Id
    app.delete("/orders/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const order = await ordersCollection.deleteOne(query);
      res.json(order);
    });

    // ---------------------------------------------------------
    // ------------------- messageCollection  -------------------
    // ----------------------------------------------------------

    //GET API messages
    app.get("/message", async (req, res) => {
      const cursor = messageCollection.find({});
      const message = await cursor.toArray();
      res.send(message);
    });

    // POST API messages
    app.post("/message", async (req, res) => {
      const messages = req.body;
      const message = await messageCollection.insertOne(messages);
      res.json(message);
    });

    // GET API messages Id
    app.get("/message/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const message = await messageCollection.findOne(query);
      res.send(message);
    });

    // Delete API messages Id
    app.delete("/message/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };
      const message = await messageCollection.deleteOne(query);
      res.json(message);
    });

    // --------------------------------------------------------------------------
    // --------------------------------Bkash Payment Gateway--------------------------------
    // --------------------------------------------------------------------------

    const bkash_headers = async () => {
      return {
        "Content-Type": "application/json",
        Accept: "application/json",
        authorization: globals.get("id_token"),
        "x-app-key": process.env.bkash_api_key,
      };
    };
    app.post("/bkash-checkout", bkashAuth, async (req, res) => {
      const details = req?.body;
      globals.set("products", details?.products);
      globals.set("userName", details?.userName);
      globals.set("userEmail", details?.userEmail);
      globals.set("payment_amount", details?.payment_amount);
      globals.set("discount", details?.discount);
      globals.set("invoice", details?.invoice);

      // console.log("Details pages", details)

      // const product = await paymentType.findOne({ _id: new ObjectId(details?.id) });
      try {
        const { data } = await axios.post(
          process.env.bkash_create_payment_url,
          {
            mode: "0011",
            payerReference: " ",
            callbackURL: `${process.env.callbackURL}/bkash/payment/callback`,
            // amount: product?.price,
            amount: details?.payment_amount,
            currency: "BDT",
            intent: "sale",
            merchantInvoiceNumber:
              details?.invoice + "-" + uuidv4().substring(0, 9),
          },
          {
            headers: await bkash_headers(),
          }
        );
        return res.status(200).send({ bkashURL: data?.bkashURL });
      } catch (error) {
        return res.status(401).send({ error: error?.message });
      }
    });

    app.get("/bkash/payment/callback", bkashAuth, async (req, res) => {
      const { paymentID, status } = req.query;

      if (status === "cancel" || status === "failure") {
        return res.redirect(
          `https://easy-mart-final-year-project.netlify.app/payment/error/${status}`
        );
      }
      if (status === "success") {
        try {
          const { data } = await axios.post(
            process?.env?.bkash_execute_payment_url,
            { paymentID },
            {
              headers: await bkash_headers(),
            }
          );
          // const product = await paymentType.findOne({
          //   _id: new ObjectId(globals.get("productId")),
          // });

          if (data && data?.statusCode === "0000") {
            const finalOrder = {
              name: globals.get("userName"),
              email: globals.get("userEmail"),
              paymentType: "Bkash",
              // package: product?.name,
              // Price: parseInt(data?.amount) || product?.price,
              // package: "Varda Mayonnaise",
              products: globals.get("products"),
              discount: globals.get("discount"),
              Price: parseInt(data?.amount) || globals.get("payment_amount"),
              customerMsisdn: data?.customerMsisdn,
              transactionStatus: data?.transactionStatus,
              paidStatus: true,
              trxID: data?.trxID,
              paymentID: data?.paymentID,
              merchantInvoiceNumber: data?.merchantInvoiceNumber,
              date: data?.paymentExecuteTime,
            };
            await ordersPaymentMethodCollection.insertOne(finalOrder);

            return res.redirect(
              `https://easy-mart-final-year-project.netlify.app/payment/success`
            );
          } else {
            return res.redirect(
              `https://easy-mart-final-year-project.netlify.app/payment/error/${data?.statusMessage}`
            );
          }
        } catch (error) {
          console.log(error);
          return res.redirect(
            `https://easy-mart-final-year-project.netlify.app/payment/error/${error?.message}`
          );
        }
      }
    });

    // 1. Get the single coupon
    app.get("/coupon", async (req, res) => {
      try {
        const coupon = await couponCollection.findOne({});
        res.status(200).json(coupon);
      } catch (error) {
        console.error("Error fetching coupon:", error);
        res.status(500).json({ message: "Failed to fetch coupon" });
      }
    });

    // Create a new coupon
    app.put("/coupon/apply", async (req, res) => {
      const { code, discountPercentage, isActive } = req.body;

      // Validate input data
      if (!code || discountPercentage === undefined || isActive === undefined) {
        return res.status(400).json({ error: "Invalid input data" });
      }

      try {
        const addCoupon = {
          code,
          discountPercentage,
          isActive,
        };

        // Update or insert the coupon in the database
        const result = await couponCollection.updateOne(
          {},
          { $set: addCoupon },
          { upsert: true }
        );

        // Send success response
        return res.status(200).json(result);
      } catch (error) {
        console.error("Error creating coupon:", error);
        return res.status(500).json({ error: "Internal server error" });
      }
    });
  } finally {
    //   await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Easy Mart Server Running*");
});

app.listen(port, () => {
  console.log("Easy Mart Server Running", port);
});
