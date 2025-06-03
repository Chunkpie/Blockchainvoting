'use client'

import React, { useState, useEffect } from 'react'
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { jwtDecode } from "jwt-decode"
import bcrypt from 'bcryptjs'
import { v4 as uuidv4 } from 'uuid'

interface Block {
  index: number
  timestamp: string
  vote: string
  voter: string
  previousHash: string
  hash: string
}

interface User {
  id: string
  username: string
  email: string
  password: string
  isAdmin: boolean
  isVerified: boolean
  twoFactorSecret?: string
}

interface DecodedToken {
  userId: string
  exp: number
}

// Simulated user database
const initialUsers: User[] = [
  { id: uuidv4(), username: 'Feizan', email: 'admin@example.com', password: bcrypt.hashSync('curl@#_&', 10), isAdmin: true, isVerified: true },
  { id: uuidv4(), username: 'user1', email: 'user1@example.com', password: bcrypt.hashSync('user123', 10), isAdmin: false, isVerified: true },
  { id: uuidv4(), username: 'Akansha', email: 'user2@example.com', password: bcrypt.hashSync('user123', 10), isAdmin: false, isVerified: true },
   { id: uuidv4(), username: 'Minakshi', email: 'user3@example.com', password: bcrypt.hashSync('user123', 10), isAdmin: false, isVerified: true },
 { id: uuidv4(), username: 'Siddh', email: 'user4@example.com', password: bcrypt.hashSync('user123', 10), isAdmin: false, isVerified: true },
]

const MAX_LOGIN_ATTEMPTS = 5
const LOGIN_COOLDOWN = 15 * 60 * 1000 // 15 minutes

function Login({ onLogin, onCreateAccount }: { onLogin: (token: string) => void, onCreateAccount: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loginAttempts, setLoginAttempts] = useState(0)
  const [lastLoginAttempt, setLastLoginAttempt] = useState(0)

  const handleLogin = () => {
    const now = Date.now()
    if (now - lastLoginAttempt < LOGIN_COOLDOWN && loginAttempts >= MAX_LOGIN_ATTEMPTS) {
      setError('Too many login attempts. Please try again later.')
      return
    }

    const user = initialUsers.find(u => u.username === username)
    if (user && bcrypt.compareSync(password, user.password)) {
      if (user.isVerified) {
        const token = generateJWT(user.id)
        onLogin(token)
        setLoginAttempts(0)
      } else {
        setError('Please verify your email before logging in.')
      }
    } else {
      setLoginAttempts(prev => prev + 1)
      setLastLoginAttempt(now)
      setError('Invalid username or password')
    }
  }

  return (
    <Card className="w-[350px] mx-auto mt-20">
      <CardHeader>
        <CardTitle>Login</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid w-full items-center gap-4">
          <div className="flex flex-col space-y-1.5">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
            />
          </div>
          <div className="flex flex-col space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
            />
          </div>
          {error && <p className="text-red-500">{error}</p>}
          <Button onClick={handleLogin}>Login</Button>
          <div className="text-center">
            <Button variant="link" onClick={onCreateAccount}>Create New Account</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function CreateAccount({ onAccountCreated, users, setUsers }: { onAccountCreated: () => void, users: User[], setUsers: React.Dispatch<React.SetStateAction<User[]>> }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [isVerifying, setIsVerifying] = useState(false)
  const [generatedCode, setGeneratedCode] = useState('')

  const handleCreateAccount = () => {
    if (!isValidPassword(password)) {
      setError('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.')
      return
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (users.some(user => user.username === username)) {
      setError('Username already exists')
      return
    }

    if (users.some(user => user.email === email)) {
      setError('Email already in use')
      return
    }

    // Generate a random 6-digit verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString()
    setGeneratedCode(code)

    // Simulate sending an email
    console.log(`Verification code ${code} sent to ${email}`)

    setIsVerifying(true)
  }

  const handleVerification = () => {
    if (verificationCode === generatedCode) {
      const newUser: User = {
        id: uuidv4(),
        username,
        email,
        password: bcrypt.hashSync(password, 10),
        isAdmin: false,
        isVerified: true
      }
      setUsers([...users, newUser])
      onAccountCreated()
    } else {
      setError('Invalid verification code')
    }
  }

  return (
    <Card className="w-[350px] mx-auto mt-20">
      <CardHeader>
        <CardTitle>Create New Account</CardTitle>
      </CardHeader>
      <CardContent>
        {!isVerifying ? (
          <div className="grid w-full items-center gap-4">
            <div className="flex flex-col space-y-1.5">
              <Label htmlFor="new-username">Username</Label>
              <Input
                id="new-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
              />
            </div>
            <div className="flex flex-col space-y-1.5">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
              />
            </div>
            <div className="flex flex-col space-y-1.5">
              <Label htmlFor="new-password">Password</Label>
              <Input
                id="new-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
              />
            </div>
            <div className="flex flex-col space-y-1.5">
              <Label htmlFor="confirm-password">Confirm Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm your password"
              />
            </div>
            {error && <p className="text-red-500">{error}</p>}
            <Button onClick={handleCreateAccount}>Create Account</Button>
          </div>
        ) : (
          <div className="grid w-full items-center gap-4">
            <p>Please enter the verification code sent to your email.</p>
            <div className="flex flex-col space-y-1.5">
              <Label htmlFor="verification-code">Verification Code</Label>
              <Input
                id="verification-code"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
                placeholder="Enter verification code"
              />
            </div>
            {error && <p className="text-red-500">{error}</p>}
            <Button onClick={handleVerification}>Verify</Button>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function Admin({ blockchain }: { blockchain: Block[] }) {
  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Admin Dashboard</h1>
      <h2 className="text-xl font-semibold mb-2">Voting Results</h2>
      {blockchain.map((block) => (
        <Card key={block.index} className="mb-2">
          <CardContent className="p-4">
            <p><strong>Block {block.index}</strong></p>
            <p>Voter: {block.voter}</p>
            <p>Vote: {block.vote}</p>
            <p>Timestamp: {block.timestamp}</p>
            <p>Hash: {block.hash}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function VotingSystem({ blockchain, setBlockchain, currentUser }: { blockchain: Block[], setBlockchain: React.Dispatch<React.SetStateAction<Block[]>>, currentUser: User }) {
  const [vote, setVote] = useState('')
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)
  const [hasVoted, setHasVoted] = useState(false)

  useEffect(() => {
    const userHasVoted = blockchain.some(block => block.voter === currentUser.username)
    setHasVoted(userHasVoted)
  }, [blockchain, currentUser])

  const calculateHash = (index: number, previousHash: string, timestamp: string, vote: string, voter: string) => {
    return bcrypt.hashSync(index + previousHash + timestamp + vote + voter, 10)
  }

  const addBlock = (vote: string, voter: string) => {
    const previousBlock = blockchain[blockchain.length - 1]
    const newIndex = previousBlock ? previousBlock.index + 1 : 0
    const newTimestamp = new Date().toISOString()
    const newHash = calculateHash(newIndex, previousBlock ? previousBlock.hash : '', newTimestamp, vote, voter)

    const newBlock = {
      index: newIndex,
      timestamp: newTimestamp,
      vote,
      voter,
      previousHash: previousBlock ? previousBlock.hash : '',
      hash: newHash,
    }

    setBlockchain([...blockchain, newBlock])
  }

  const handleVote = () => {
    if (hasVoted) {
      setMessage({ type: 'error', text: 'You have already cast your vote.' })
      return
    }

    if (vote) {
      addBlock(vote, currentUser.username)
      setVote('')
      setHasVoted(true)
      setMessage({ type: 'success', text: 'Your vote has been cast successfully!' })
    } else {
      setMessage({ type: 'error', text: 'Please enter your vote before submitting.' })
    }
  }

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-2xl font-bold mb-4">Blockchain Voting System</h1>
      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Cast Your Vote</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid w-full items-center gap-4">
            <div className="flex flex-col space-y-1.5">
              <Label htmlFor="vote">Your Vote</Label>
              <Input
                id="vote"
                value={vote}
                onChange={(e) => setVote(sanitizeInput(e.target.value))}
                placeholder="Enter your vote"
                disabled={hasVoted}
              />
            </div>
            <Button onClick={handleVote} disabled={hasVoted}>
              {hasVoted ? 'Vote Cast' : 'Submit Vote'}
            </Button>
          </div>
        </CardContent>
      </Card>
      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : 'default'}>
          <AlertTitle>{message.type === 'error' ? 'Error' : 'Success'}</AlertTitle>
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}

function TwoFactorAuth({ onVerify }: { onVerify: () => void }) {
  const [code, setCode] = useState('')
  const [error, setError] = useState('')

  const handleVerify = () => {
    // In a real application, you would verify the code against the user's secret
    if (code === '123456') {
      onVerify()
    } else {
      setError('Invalid code')
    }
  }

  return (
    <Card className="w-[350px] mx-auto mt-20">
      <CardHeader>
        <CardTitle>Two-Factor Authentication</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid w-full items-center gap-4">
          <div className="flex flex-col space-y-1.5">
            <Label htmlFor="2fa-code">Enter 2FA Code</Label>
            <Input
              id="2fa-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Enter 6-digit code"
            />
          </div>
          {error && <p className="text-red-500">{error}</p>}
          <Button onClick={handleVerify}>Verify</Button>
        </div>
      </CardContent>
    </Card>
  )
}

export default function Component() {
  const [user, setUser] = useState<User | null>(null)
  const [blockchain, setBlockchain] = useState<Block[]>([])
  const [users, setUsers] = useState<User[]>(initialUsers)
  const [showCreateAccount, setShowCreateAccount] = useState(false)
  const [showTwoFactor, setShowTwoFactor] = useState(false)
  const [token, setToken] = useState<string | null>(null)

  useEffect(() => {
    const storedToken = localStorage.getItem('token')
    if (storedToken) {
      const decodedToken = jwtDecode(storedToken) as DecodedToken
      if (decodedToken.exp * 1000 > Date.now()) {
        setToken(storedToken)
        const user = users.find(u => u.id === decodedToken.userId)
        if (user) {
          setUser(user)
        }
      } else {
        localStorage.removeItem('token')
      }
    }
  }, [users])

  const handleLogin = (newToken: string) => {
    setToken(newToken)
    localStorage.setItem('token', newToken)
    const decodedToken = jwtDecode(newToken) as DecodedToken
    const loggedInUser = users.find(u => u.id === decodedToken.userId)
    if (loggedInUser) {
      if (loggedInUser.twoFactorSecret) {
        setShowTwoFactor(true)
      } else {
        setUser(loggedInUser)
      }
    }
  }

  const handleLogout = () => {
    setUser(null)
    setToken(null)
    localStorage.removeItem('token')
  }

  const handleCreateAccount = () => {
    setShowCreateAccount(true)
  }

  const handleAccountCreated = () => {
    setShowCreateAccount(false)
  }

  const handleTwoFactorVerified = () => {
    setShowTwoFactor(false)
    if (token) {
      const decodedToken = jwtDecode(token) as DecodedToken
      const loggedInUser = users.find(u => u.id === decodedToken.userId)
      if (loggedInUser) {
        setUser(loggedInUser)
      }
    }
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {user && (
        <nav className="bg-white shadow-sm">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex">
                <div className="flex-shrink-0 flex items-center">
                  <h1 className="text-lg font-semibold">Blockchain Voting</h1>
                </div>
              </div>
              <div className="flex items-center">
                <span className="mr-4">Welcome, {user.username}</span>
                <Button onClick={handleLogout}>Logout</Button>
              </div>
            </div>
          </div>
        </nav>
      )}
      {!user ? (
        showCreateAccount ? (
          <CreateAccount onAccountCreated={handleAccountCreated} users={users} setUsers={setUsers} />
        ) : showTwoFactor ? (
          <TwoFactorAuth onVerify={handleTwoFactorVerified} />
        ) : (
          <Login onLogin={handleLogin} onCreateAccount={handleCreateAccount} />
        )
      ) : user.isAdmin ? (
        <Admin blockchain={blockchain} />
      ) : (
        <VotingSystem blockchain={blockchain} setBlockchain={setBlockchain} currentUser={user} />
      )}
    </div>
  )
}

// Utility functions
function generateJWT(userId: string): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({ userId, exp: Math.floor(Date.now() / 1000) + (60 * 60) }))
  const signature = btoa(header + '.' + payload) // In a real app, this would be signed with a secret key
  return `${header}.${payload}.${signature}`
}

function isValidPassword(password: string): boolean {
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
  return regex.test(password)
}

function sanitizeInput(input: string): string {
  return input.replace(/[<>&'"]/g, '')
}