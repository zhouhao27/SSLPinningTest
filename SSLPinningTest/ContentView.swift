//
//  ContentView.swift
//  SSLPinningTest
//
//  Created by Zhou Hao on 25/7/23.
//

import SwiftUI
import Observation

class User: Codable {
    let id: Int
    let name: String
    let username: String
    let email: String
    
    init(id: Int, name: String, username: String, email: String) {
        self.id = id
        self.name = name
        self.username = username
        self.email = email
    }
}

struct ContentView: View {
    var vm = UserViewModel()
    @State private var isPublicKeyPinning : Bool = false
    
    let user = User(id: 1, name: "Zhou Hao", username: "zhouhao", email: "zhouhao@email.com")
    var body: some View {
        VStack {
            HStack {
                Spacer()
                Text(isPublicKeyPinning ? "Public Pinning" : "Certificate Pinning")
                Toggle(isOn: $isPublicKeyPinning) {
                }
            }
            .padding(.leading, 50)
            
            if vm.username.isEmpty {
                Text("Please click Load User")
                    .font(.title.bold())
            } else {
                
                if vm.loading {
                    Text("Loading...")
                        .font(.title.bold())
                } else {
                    
                    Text(vm.username)
                        .font(.title.bold())
                    Text(vm.email)
                        .foregroundStyle(.secondary)
                }
            }
            
            Button {
                Task {
                    await vm.reloadData(publicKeyPinning: isPublicKeyPinning)
                }
            } label: {
                Text("Load User")
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 30)
            
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
