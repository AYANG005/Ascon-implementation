from Perm import perm
import random
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from keras.callbacks import ModelCheckpoint, LearningRateScheduler, CSVLogger
from keras.models import Model
from keras.layers import Dense, Conv1D, Input, Reshape, Permute, Add, Flatten, BatchNormalization, Activation
from keras.regularizers import l2

def gen_inputs(data_size,input_diff):
    choice = [0,1]
    data = []
    diff = []
    for i in range(data_size):
        x1 = random.getrandbits(320) #generate random input
        temp = random.choice(choice) #1 or 0 i.e fixed or random input diff
        if temp == 1: x2 = x1 ^ input_diff #generate second input with inputdiff
        elif temp == 0: x2 = random.getrandbits(320) #generate second input randomly
        entry1 = []
        entry2 = []
        y1 = perm(x1,1) #perm outputs
        y2 = perm(x2,1) #perm outputs

        for j in range(0,320): #converting yis to bitwise entries in string
            entry1.insert(0,((y1 >> j) & 1))
            entry2.insert(0, ((y2 >> j) & 1))
        entry1 = np.asarray(entry1).astype(np.uint8)
        entry2 = np.asarray(entry2).astype(np.uint8)
        entry = np.concatenate((entry1, entry2)) #(320 bit output,320 bit output) i.e 640 bit list with bitwise entries
        if temp == 1: diff+=[1]
        elif temp == 0: diff+=[0] #if random input diff
        data.append(entry) #add entry to dataset

    data = np.array(data)
    diff = np.array(diff)

    return data, diff

def neural_net(num_filters=32, num_outputs=1, d1=64, d2=64, ks=3,depth=5, reg_param=0.0001, final_activation='sigmoid'):
  #Input and preprocessing layers
  inp = Input(shape=(640,))
  rs = Reshape((10, 64))(inp)
  perm = Permute((2, 1))(rs)

  #single residual layer(bit sliced)(block 1)
  conv0 = Conv1D(num_filters, kernel_size=1, padding='same', kernel_regularizer=l2(reg_param))(perm)
  conv0 = BatchNormalization()(conv0)
  conv0 = Activation('relu')(conv0)

  #add residual blocks(blocks 2-i)
  shortcut = conv0;
  for i in range(depth):
    conv1 = Conv1D(num_filters, kernel_size=ks, padding='same', kernel_regularizer=l2(reg_param))(shortcut)
    conv1 = BatchNormalization()(conv1)
    conv1 = Activation('relu')(conv1)
    conv2 = Conv1D(num_filters, kernel_size=ks, padding='same',kernel_regularizer=l2(reg_param))(conv1)
    conv2 = BatchNormalization()(conv2)
    conv2 = Activation('relu')(conv2)
    shortcut = Add()([shortcut, conv2])

  #add classification block
  flat1 = Flatten()(shortcut)
  dense1 = Dense(d1,kernel_regularizer=l2(reg_param))(flat1)
  dense1 = BatchNormalization()(dense1)
  dense1 = Activation('relu')(dense1)
  dense2 = Dense(d2, kernel_regularizer=l2(reg_param))(dense1)
  dense2 = BatchNormalization()(dense2)
  dense2 = Activation('relu')(dense2)
  out = Dense(num_outputs, activation=final_activation, kernel_regularizer=l2(reg_param))(dense2)
  model = Model(inputs=inp, outputs=out)
  return(model)

def cyclic_lr(n, beta, alpha):
  to_return = lambda i: alpha + (n - i % (n+1))/n * (beta - alpha);
  return(to_return);

#df_X, df_y = gen_inputs(10**7,2**319)
#np.save("data_X.npy", df_X)
#np.save("data_y.npy", df_y)
df_X = np.load("data_X.npy",allow_pickle=True)
df_y = np.load("data_y.npy",allow_pickle=True)

num_epochs = 1
depth = 1
batch_size = 5000

net = neural_net(depth=depth, reg_param=10**-5) #generate network
net.compile(optimizer='adam',loss='mse',metrics=['acc'])

X_train, X_test, y_train, y_test = train_test_split(df_X, df_y, test_size=0.2, random_state=42)
#set up model checkpoint
checkpoint = ModelCheckpoint('./Models/best_depth:'+str(depth)+'.h5', monitor='val_loss', save_best_only = True)
#CSV_Logger
log_csv = CSVLogger('./Models/log_depth='+str(depth)+'.csv', separator=',', append=False)
#cyclic learnrate scheduler
lr = LearningRateScheduler(cyclic_lr(9,0.002, 0.0001))

fitted = net.fit(X_train,y_train,epochs=num_epochs,batch_size=batch_size,validation_data=(X_test, y_test), callbacks=[lr,checkpoint, log_csv])
print("Best validation accuracy: ", np.max(fitted.history['val_acc']))


