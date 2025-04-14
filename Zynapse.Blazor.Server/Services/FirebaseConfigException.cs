namespace Zynapse.Blazor.Server.Services;

public class FirebaseConfigException : Exception
{
    public string DetailedMessage { get; }

    public FirebaseConfigException(string message, string detailedMessage)
        : base(message)
    {
        DetailedMessage = detailedMessage;
    }

    public override string ToString()
    {
        return $"{Message}\n\n{DetailedMessage}";
    }
} 