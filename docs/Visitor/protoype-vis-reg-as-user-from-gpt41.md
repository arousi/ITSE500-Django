# Prototype to show the inability of LLMs to produce SWE Diagrams for Modelling Requirements

## First incorrect diagram

User           Web/Mobile         Django Server         RegisterSerializer      Custom_User/DB

 |                  |                   |                      |                      |
 |---[1. Register]->|                   |                      |                      |
 |                  |---[2. POST]------>|                      |                      |
 |                  |                   |--[3. create]-------->|                      |
 |                  |                   |--[4. validate]------>|                      |
 |                  |                   |                      |                      |
 |                  |                   |<--[5a. valid]--------|                      |
 |                  |                   |--[6. create user]--->|---[7. save]--------->|
 |                  |                   |<--[8. user saved]----|                      |
 |                  |                   |--[9. send PIN email] |                      |
 |                  |                   |--[10. issue JWT]-----|                      |
 |                  |<--[11. 201 + user/convos]---------------|                       |
 |                  |                   |                      |                      |
 |                  |                   |<--[5b. invalid]------|                      |
 |                  |                   |--[6. lookup by email/uuid/username]-------->|
 |                  |                   |<--[7. user found?]---|                      |
 |                  |                   |--[8. issue JWT]------|                      |
 |                  |                   |--[9. fetch convos]-->|                      |
 |                  |                   |<--[10. convos]-------|                      |
 |                  |<--[11. 201 + user/convos]---------------|                       |
 |                  |                   |                      |                      |
 |                  |                   |--[7. user not found] |                      |
 |                  |<--[8. 400 error]------------------------|                       |

## Second incorrect diagram

|User|           |Web/Mobile|         |Django Server|         |RegisterSerializer|      |Custom_User/DB|
 |                  |                   |                      |                      |
 |---[1. Register]->|                   |                      |                      |
 |                  |---[2. POST]------>|                      |                      |
 |                  |                   |--[3. create]-------->|                      |
 |                  |                   |--[4. validate]------>|                      |
 |                  |                   |<--[5. valid?]--------|                      |
 |                  |                   |                      |                      |
 |                  |                   |--[6a. if valid]------|                      |
 |                  |                   |   [create user]      |                      |
 |                  |                   |   [hash password]    |                      |
 |                  |                   |   [generate PIN]     |                      |
 |                  |                   |   [send PIN email]   |                      |
 |                  |                   |                      |                      |
 |                  |                   |--[6b. if invalid]----|                      |
 |                  |                   |   [lookup by email/uuid/username]           |
 |                  |                   |   [if found, use user]                      |
 |                  |                   |   [if not found, return 400]                |
 |                  |                   |                      |                      |
 |                  |                   |--[7. issue JWT]------|                      |
 |                  |                   |--[8. fetch convos]-->|                      |
 |                  |                   |<--[9. convos]--------|                      |
 |                  |<--[10. 201 + user/convos]----------------|                      |

Both diagrams elicit incorrect behaviour of the `RegisterView` which would return any data found if all went correct
it also doesn't take in consideration that the `password` is optional in the Request, it thinks of it to be valid or not
