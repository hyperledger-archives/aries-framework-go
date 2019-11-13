### Project Structure

The project's components are organized, conceptually, into 3 layers:
- Business Logic: provides APIs for framework users
- Client Layer: handles protocol flows, dispatches to other layers
- Service Layer: components (DIDs, crypto, etc)

As a user, what do you do:
- Business Logic
  - initialize the framework (Aries framework object)
  - register for events using the Rest API or Native Go API
  - handle events
- Service Layer
  - Create custom plugins for components, inject them into the framework
