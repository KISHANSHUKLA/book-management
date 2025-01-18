<?php

require __DIR__ . '/vendor/autoload.php';

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Firebase\JWT\JWT;

use Firebase\JWT\Key;
use GuzzleHttp\Client;

error_reporting(E_ALL);
ini_set('display_errors', '1');

header("Content-Type: application/json");

// Start session to store books across requests
session_start();

if (!isset($_SESSION['books'])) {
    $_SESSION['books'] = [];
}
// Autoincrement ID for new books
if (!isset($_SESSION['idCounter'])) {
    $_SESSION['idCounter'] = 1;
}
define('SECRET_KEY', 'your-secret-key');
// Book class
class Book
{
    public $id;
    public $title;
    public $author;
    public $published_year;

    public function __construct($id, $title, $author, $published_year)
    {
        $this->id = $id;
        $this->title = $title;
        $this->author = $author;
        $this->published_year = $published_year;
    }
}

// Users storage (In a real application, use a database)
$users = [
    'testuser' => [
        'password' => password_hash('password123', PASSWORD_BCRYPT) // Hashed password
    ]
];

// Helper functions
function findBookById($id)
{
    foreach ($_SESSION['books'] as $book) {
        if ($book->id == $id) {
            return $book;
        }
    }
    return null;
}

function getRequestBody(Request $request)
{
    return json_decode($request->getContent(), true);
}

function authenticate(Request $request)
{

    // Get the Authorization header
    $authHeader = $request->headers->get('Authorization');
    if (!$authHeader) {
        return null;
    }

    // Extract the token from the Authorization header (Bearer token)
    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $token = $matches[1];
        try {
            // Use the Key object for decoding
            $decoded = JWT::decode($token, new Key(SECRET_KEY, 'HS256'));
            return $decoded;
        } catch (Exception $e) {
            // Handle decoding errors
            return null;
        }
    }
    return null;
}
function generateToken($username)
{

    $issuedAt = time();
    $expirationTime = $issuedAt + 3600;  // jwt valid for 1 hour from the issued time
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expirationTime,
        'username' => $username
    ];

    // Include the algorithm explicitly if using JWT version 6+
    return JWT::encode($payload, SECRET_KEY, 'HS256');
}

// Route handling
$request = Request::createFromGlobals();
$method = $request->getMethod();
$uri = $request->getPathInfo();

// Store users in session (initialize if not set)
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [];
}


if ($uri === '/api/books/generate-summary') {

    if ($method === 'POST') {

        $user = authenticate($request);

        if (!$user) {
            $response = new Response(json_encode(["error" => "Unauthorized access"]), 401);
        } else {

            $data = getRequestBody($request);

            $bookId = $data['book_id'] ?? null;

            if (!$bookId) {
                $response = new Response(json_encode(["error" => "Book ID is required"]), 400);
            } else {

                $book = findBookById($bookId);

                if (!$book) {
                    $response = new Response(json_encode(["error" => "Book not found"]), 404);
                } else {
                    $client = new Client();

                    try {
                        // Use environment variable for the Hugging Face API token
                        $huggingFaceApiUrl = "https://api-inference.huggingface.co/models/openai-community/gpt2";
                        $huggingFaceApiToken = ''; // Load the token securely;

                        $aiRequest = [
                            'headers' => [
                                'Authorization' => "Bearer $huggingFaceApiToken",
                                'Content-Type' => 'application/json'
                            ],
                            'json' => [
                                'inputs' => "Generate a summary for a book titled '{$book->title}' by '{$book->author}' published in {$book->published_year}."
                            ]
                        ];


                        $aiResponse = $client->post($huggingFaceApiUrl, $aiRequest);

                        $aiResult = json_decode($aiResponse->getBody()->getContents(), true);

                        if (!empty($aiResult) && isset($aiResult[0]['generated_text'])) {

                            $summary = $aiResult[0]['generated_text'];

                            $response = new Response(json_encode([
                                "book" => $book,
                                "summary" => $summary
                            ]), 200);
                        } else {
                            $response = new Response(json_encode(["error" => "Failed to generate summary"]), 500);
                        }
                    } catch (Exception $e) {
                        error_log($e->getMessage());
                        $response = new Response(json_encode(["error" => "Error communicating with Hugging Face API"]), 500);
                    }
                }
            }
        }
    } else {
        $response = new Response(json_encode(["error" => "Method not allowed"]), 405);
    }
}
// Register route
if ($uri === '/api/register' && $method === 'POST') {
    $data = getRequestBody($request);

    if (!isset($data['username'], $data['password'])) {
        $response = new Response(json_encode(["error" => "Username and password are required"]), 400);
    } else {
        $username = $data['username'];
        if (isset($_SESSION['users'][$username])) {
            $response = new Response(json_encode(["error" => "User already exists"]), 400);
        } else {
            $_SESSION['users'][$username] = [
                'password' => password_hash($data['password'], PASSWORD_BCRYPT)
            ];
            $response = new Response(json_encode(["message" => "User registered successfully"]), 201);
        }
    }
}

// Login route
elseif ($uri === '/api/login' && $method === 'POST') {
    $data = getRequestBody($request);

    if (!isset($data['username'], $data['password'])) {
        $response = new Response(json_encode(["error" => "Username and password are required"]), 400);
    } else {

        $username = $data['username'];
        if (isset($_SESSION['users'][$username]) && password_verify($data['password'], $_SESSION['users'][$username]['password'])) {

            $token = generateToken($username);

            $response = new Response(json_encode(["token" => $token]), 200);
        } else {
            $response = new Response(json_encode(["error" => "Invalid credentials"]), 401);
        }
    }
} elseif (preg_match("#^/api/books/?(\\d+)?$#", $uri, $matches)) {
    $bookId = isset($matches[1]) ? (int)$matches[1] : null;

    // Secure endpoints: Authenticate user
    $user = authenticate($request);
    if (!$user) {
        $response = new Response(json_encode(["error" => "Unauthorized"]), 401);
    } else {
        switch ($method) {
            case 'GET':
                if ($bookId) {
                    // Retrieve a single book by ID
                    $book = findBookById($bookId);
                    if ($book) {
                        $response = new Response(json_encode($book), 200);
                    } else {
                        $response = new Response(json_encode(["error" => "Book not found"]), 404);
                    }
                } else {
                    // Retrieve all books
                    if (empty($_SESSION['books'])) {
                        $response = new Response(json_encode(["message" => "No books found"]), 404);
                    } else {
                        $response = new Response(json_encode(array_values($_SESSION['books'])), 200);
                    }
                }
                break;

            case 'POST':
                // Add a new book
                $data = getRequestBody($request);
                if (!isset($data['title'], $data['author'], $data['published_year'])) {
                    $response = new Response(json_encode(["error" => "Invalid input"]), 400);
                    break;
                }

                $newBook = new Book($_SESSION['idCounter']++, $data['title'], $data['author'], $data['published_year']);
                $_SESSION['books'][] = $newBook;
                $response = new Response(json_encode($newBook), 201);
                break;

            case 'PUT':
                // Update an existing book
                if (!$bookId) {
                    $response = new Response(json_encode(["error" => "Book ID required"]), 400);
                    break;
                }

                $book = findBookById($bookId);
                if (!$book) {
                    $response = new Response(json_encode(["error" => "Book not found"]), 404);
                    break;
                }

                $data = getRequestBody($request);
                if (isset($data['title'])) $book->title = $data['title'];
                if (isset($data['author'])) $book->author = $data['author'];
                if (isset($data['published_year'])) $book->published_year = $data['published_year'];

                $response = new Response(json_encode($book), 200);
                break;

            case 'DELETE':
                // Delete a book by ID
                if (!$bookId) {
                    $response = new Response(json_encode(["error" => "Book ID required"]), 400);
                    break;
                }

                foreach ($_SESSION['books'] as $index => $book) {
                    if ($book->id == $bookId) {
                        unset($_SESSION['books'][$index]);
                        // Return success message after deletion
                        $response = new Response(json_encode(["message" => "Book deleted successfully"]), 200);
                        break 2;
                    }
                }
                $response = new Response(json_encode(["error" => "Book not found"]), 404);
                break;

            default:
                $response = new Response(json_encode(["error" => "Method not allowed"]), 405);
                break;
        }
    }
}

$response->send();