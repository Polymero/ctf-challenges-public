#!/usr/local/bin/python
#
# Polymero
#

# Imports
from DiffieChat import *
import os

# Local imports
FLAG = os.environ.get('FLAG', 'flag{spl4t_th3m_bugs}').encode()

#------------------------------------------------------------------------------------------------------------------
# INTERACTION STRUCTURE
#------------------------------------------------------------------------------------------------------------------
hdr = r"""|
|      ____   _  ____ ____ _          ______ __            __ 
|     / __ \ (_)/ __// __/(_)___     / ____// /_   ____ _ / /_
|    / / / // // /_ / /_ / // _ \   / /    / __ \ / __ `// __/
|   / /_/ // // __// __// //  __/  / /___ / / / // /_/ // /_  
|  /_____//_//_/  /_/  /_/ \___/   \____//_/ /_/ \__,_/ \__/  
|                                                  Ver {}
|                  
|  ~ Server parameters ::
|    g = {}
|    p = {}
|                              
|  ~ WELCOME BACK xXx_h4x0r_xXx !
|"""

menu = r"""|
|  ~ Options ::
|    [1] Show account info
|    [2] List my active chats
|    [3] Open a chat
|
|  ~ Developer options ::
|    [4] Send a raw packet to the Server
|
|  ~ [0] Exit
|"""

chat_menu = r"""|
|  ~ Chat options ::
|    [1] Send
|    [2] Go back
|"""

def __chall_1__():

    FLAGREQUEST = False
    
    # Set up Server
    S = DiffieServer()
    
    # Register Clients
    A = S.register('Alice')
    B = S.register('Bob')
    C = S.register('Charlie')
    P = S.register('xXx_h4x0r_xXx') # You
    
    # Create Chats
    #AB = A.create_chat([A,B])
    AP = P.create_chat([A,P])
    ABCP = A.create_chat([A,B,C,P], 'Party People')
    BP = P.create_chat([B,P])
    
    # B Chat
    B.send(P.key_ID, "My mum wants me to go to the store for her...")
    B.send(P.key_ID, "brb")
    
    print(hdr.format(VER, S.g, S.p))

    while True:

        try:
            
            print(menu)
            choice = input('|  >> ')
            
            if choice == '1':
                print('|\n|\n|  ~ Account info ::\n|    name   = {}\n|    usr_id = {}\n|    usr_pk = {}'.format(P.name, P.key_ID, P.pk))
                continue
            
            if choice == '2':
                P.show_chats() 
                continue
                
            if choice == '3':
                print('|\n|  ~ Which chat would you like to open?\n|')
                pos_chats = []
                for i,ch in enumerate(P.chats):
                    chat = P.chats[ch]
                    pos_chats += [chat]
                    print('|    [{}] {}'.format(i, chat['name']))
                print('|')
                choice = input('|  >> ')

                chat     = pos_chats[int(choice)]
                raw, msg = chat['chat_obj'].read()
                name     = chat['name']
                key_ID   = chat['key_ID']

                print('|\n|')
                if len(raw) == 0:
                    print('|   ~ No messages yet.\n|')
                else:
                    msglst = ['<']
                    for i in range(len(raw)):
                        if msg[i]['SID'] == P.name:
                            msglst += ['< ~ {} :: ({})'.format(msg[i]['SID'], msg[i]['UTS']), '<' + msg[i]['MSG'], '<']
                        else:
                            msglst += ['>({}) :: {} ~ '.format(msg[i]['UTS'], msg[i]['SID']), '>' + msg[i]['MSG'], '>']
                    maxlen = max(len(i) for i in msglst) + 8
                    print('| +' + (maxlen + 2) * '-' + '+')
                    for i in msglst:
                        if i[0] == '<':
                            print('| | {:<{n}} |'.format(i[1:], n=maxlen))
                        elif i[0] == '>':
                            print('| | {:>{n}} |'.format(i[1:], n=maxlen))
                    print('| +' + (maxlen + 2) * '-' + '+')


                print(chat_menu)
                choice = input('|  >> ')
                
                if choice == '1':
                    print('|\n|  ~ Sending to {}:'.format(name))
                    msg_to_send = input('|  >> ')

                    P.send(key_ID, msg_to_send)

                    raw, msg = chat['chat_obj'].read()
                    print('|')
                    for i in range(len(raw)):
                        print('|  ~ {} :: ({})\n|    {}\n|'.format(msg[i]['SID'], msg[i]['UTS'], msg[i]['MSG']))

                    # Role-play Alice
                    if key_ID == A.key_ID:

                        if 'flag' in msg_to_send:

                            A.send(P.key_ID, "Mmh... The flag is our shared secret after all.")
                            A.send(P.key_ID, "If the others agree to give you the flag you can have it.")
                            A.send(P.key_ID, "I'll ask in the group chat")

                            A.send(ABCP['key_ID'], "Yo peeps, shall we give h4x0r our flag?")
                            C.send(ABCP['key_ID'], "Fine with me ;)")
                            A.send(ABCP['key_ID'], "What about you Bob?")
                            A.send(ABCP['key_ID'], "Bob???")
                            A.send(ABCP['key_ID'], "Mmh... We can only give you the flag if Bob agrees to it.")

                            FLAGREQUEST = True

                        else:
                            A.send(P.key_ID, "Keep it down will ya, I'm working on this annoying challenge...")

                    # Role-play Party People
                    if key_ID == ABCP['key_ID']:

                        if FLAGREQUEST:
                            C.send(ABCP['key_ID'], "We'll have to wait until Bob comes back, sorry")

                        else:
                            C.send(ABCP['key_ID'], "These challs are sooo hard ;C")
                            A.send(ABCP['key_ID'], "IKR")

                    if choice == '2': 
                        continue

            if choice == '4':

                print('|\n|  ~ Sending packet to the Server ::')
                packet_to_set = input('|  >> ')

                try:
                    S.handle_packet(packet_to_set)
                except:
                    print('|\n|  ~ ERROR :: Invalid packet.')
                    continue

                last_msg = P.chats[ABCP['key_ID']]['chat_obj'].read()[1][-1]['MSG'].lower()
                if any(i in last_msg for i in ['sure','yes','fine','ok']):
                    A.send(ABCP['key_ID'], "Alright here you go then")
                    A.send(ABCP['key_ID'], FLAG)

                continue
            
            if choice in ['exit','quit','q','0']:
                print('|\n|  ~ Bye!\n|')
                break

        except KeyboardInterrupt:
            print('\n|\n|\n|  ~ Bye!\n|')
            break

        except:
            print('|\n|  ~ ERROR :: Something went wrong.')
            continue

__chall_1__()